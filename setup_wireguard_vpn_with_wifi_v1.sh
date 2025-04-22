#!/bin/sh
# nordlynx-router.sh — Multi-WiFi Secure Split-Tunnel VPN with dynamic WireGuard configs
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 /etc/wireguard/yourname.conf" >&2
  exit 1
fi

CONF="$1"
NAME=$(basename "$CONF" .conf)

readonly LOG="/tmp/nordlynx-router-${NAME}.log"
exec > >(tee -a "$LOG") 2>&1

log() { printf "\033[1;34m==> %s\033[0m\n" "$@"; }
err() { printf "\033[1;31m❌ %s\033[0m\n" "$@" >&2; }
run() { log "+ $*"; "$@" || { err "FAILED: $*"; exit 1; }; }
try() { log "+ $* (ignore errors)"; "$@" || true; }

# Dynamically choose next available wgX interface
WG_IF=$(for i in $(seq 0 9); do ip link show wg$i >/dev/null 2>&1 || { echo wg$i; break; }; done)
[ -z "$WG_IF" ] && { err "No available wgX slot found"; exit 1; }
VPNLAN="vpnlan_${NAME}"
VPNLAN_IP="192.168.$((RANDOM % 100 + 100)).1"
VPNLAN_NETWORK="${VPNLAN_IP%.*}.0/24"
WIFI_SSID="$NAME"
WIFI_PWD="ChangeMe1234"
VPN_TABLE_ID=$((100 + $(echo "$NAME" | md5sum | cut -c1-6 | tr -cd '0-9' | tail -c3)))
VPN_TABLE_NAME="$NAME"
VPN_RULE_PRIORITY=100

log "$(date) – Setting up VPN for $NAME from $CONF"

[ -f "$CONF" ] || { err "Config missing: $CONF"; exit 1; }

while read -r key val; do
  case "$key" in
    PrivateKey) PRIVATE_KEY=$val ;;
    Address) ADDRESS=$val ;;
    DNS) DNS1=$(echo "$val" | cut -d, -f1)
         DNS2=$(echo "$val" | cut -d, -f2 | tr -d ',') ;;
    PublicKey) PUBKEY=$val ;;
    Endpoint) ENDPOINT=$val ;;
    PersistentKeepalive) PERSIST=$val ;;
  esac
done <<EOF
$(awk '/^(PrivateKey|Address|DNS|PublicKey|Endpoint|PersistentKeepalive)/{print $1, $3}' "$CONF")
EOF

ENDPOINT_HOST=${ENDPOINT%:*}
ENDPOINT_PORT=${ENDPOINT##*:}

log "Cleaning previous configuration..."
for item in \
  network."$WG_IF" network.peer_${NAME} network."$VPNLAN" \
  dhcp."$VPNLAN" wireless.ap_${NAME} \
  firewall.clients_${NAME} firewall.tunnel_${NAME} firewall.icmp_${NAME}; do
  try uci delete "$item"
done

log "Setting up WireGuard interface $WG_IF"
uci batch <<EOF
set network.$WG_IF=interface
set network.$WG_IF.proto='wireguard'
set network.$WG_IF.private_key='$PRIVATE_KEY'
add_list network.$WG_IF.addresses='$ADDRESS'
set network.$WG_IF.peerdns='0'
add_list network.$WG_IF.dns='$DNS1'
add_list network.$WG_IF.dns='$DNS2'
set network.$WG_IF.ipv6='auto'
set network.$WG_IF.auto='1'

set network.peer_${NAME}='wireguard_$WG_IF'
set network.peer_${NAME}.public_key='$PUBKEY'
set network.peer_${NAME}.allowed_ips='0.0.0.0/0,::/0'
set network.peer_${NAME}.endpoint_host='$ENDPOINT_HOST'
set network.peer_${NAME}.endpoint_port='$ENDPOINT_PORT'
set network.peer_${NAME}.persistent_keepalive='$PERSIST'
set network.peer_${NAME}.description='$NAME'
EOF
run uci commit network
run /etc/init.d/network reload

log "Bringing up interface $WG_IF"
run ifup "$WG_IF"

COUNT=0
until ip link show "$WG_IF" >/dev/null 2>&1; do
  sleep 1
  COUNT=$((COUNT + 1))
  [ "$COUNT" -gt 15 ] && err "$WG_IF interface not found" && exit 1
done

COUNT=0
until ip addr show dev "$WG_IF" | grep -q 'inet '; do
  sleep 1
  COUNT=$((COUNT + 1))
  [ "$COUNT" -gt 15 ] && err "$WG_IF did not receive an IP address" && exit 1
done

log "Creating VPN LAN interface $VPNLAN"
uci batch <<EOF
set network.$VPNLAN='interface'
set network.$VPNLAN.type='bridge'
set network.$VPNLAN.proto='static'
set network.$VPNLAN.ipaddr='$VPNLAN_IP'
set network.$VPNLAN.netmask='255.255.255.0'
set network.$VPNLAN.force_link='1'
set network.$VPNLAN.delegate='0'
set network.$VPNLAN.peerdns='0'
set network.$VPNLAN.dns='$DNS1'
EOF
[ -n "$DNS2" ] && run uci add_list network.$VPNLAN.dns="$DNS2"
run uci commit network

log "Setting up DHCP for $VPNLAN"
uci batch <<EOF
set dhcp.$VPNLAN='dhcp'
set dhcp.$VPNLAN.interface='$VPNLAN'
set dhcp.$VPNLAN.start='100'
set dhcp.$VPNLAN.limit='150'
set dhcp.$VPNLAN.leasetime='12h'
set dhcp.$VPNLAN.force='1'
set dhcp.$VPNLAN.dhcpv6='server'
set dhcp.$VPNLAN.ra='server'
EOF
uci delete dhcp.$VPNLAN.dhcp_option 2>/dev/null || true
uci add_list dhcp.$VPNLAN.dhcp_option="6,$DNS1${DNS2:+,$DNS2}"
run uci commit dhcp

log "Setting up Wi-Fi AP: $WIFI_SSID"
RADIO=$(uci show wireless | grep '=wifi-device' | head -n1 | cut -d. -f2 | cut -d= -f1)
[ -n "$RADIO" ] || { err "No Wi-Fi radio found"; exit 1; }
try uci delete wireless.ap_${NAME}
uci batch <<EOF
set wireless.ap_${NAME}='wifi-iface'
set wireless.ap_${NAME}.device='$RADIO'
set wireless.ap_${NAME}.mode='ap'
set wireless.ap_${NAME}.network='$VPNLAN'
set wireless.ap_${NAME}.ssid='$WIFI_SSID'
set wireless.ap_${NAME}.encryption='sae-mixed'
set wireless.ap_${NAME}.key='$WIFI_PWD'
set wireless.ap_${NAME}.disabled='0'
set wireless.ap_${NAME}.isolate='1'
set wireless.ap_${NAME}.ieee80211w='1'
set wireless.ap_${NAME}.wps_pushbutton='0'
EOF
run uci commit wireless
run wifi reload

log "Configuring firewall zones"
uci batch <<EOF
set firewall.clients_${NAME}='zone'
set firewall.clients_${NAME}.name='clients_${NAME}'
set firewall.clients_${NAME}.network='$VPNLAN'
set firewall.clients_${NAME}.input='ACCEPT'
set firewall.clients_${NAME}.output='ACCEPT'
set firewall.clients_${NAME}.forward='REJECT'

set firewall.tunnel_${NAME}='zone'
set firewall.tunnel_${NAME}.name='tunnel_${NAME}'
set firewall.tunnel_${NAME}.network='$WG_IF'
set firewall.tunnel_${NAME}.input='REJECT'
set firewall.tunnel_${NAME}.output='ACCEPT'
set firewall.tunnel_${NAME}.forward='REJECT'
set firewall.tunnel_${NAME}.masq='1'
set firewall.tunnel_${NAME}.mtu_fix='1'

set firewall.forward_${NAME}='forwarding'
set firewall.forward_${NAME}.src='clients_${NAME}'
set firewall.forward_${NAME}.dest='tunnel_${NAME}'

set firewall.icmp_${NAME}='rule'
set firewall.icmp_${NAME}.name='Allow-ICMP-${NAME}'
set firewall.icmp_${NAME}.src='clients_${NAME}'
set firewall.icmp_${NAME}.proto='icmp'
set firewall.icmp_${NAME}.target='ACCEPT'
EOF
run uci commit firewall

log "Restarting services"
run /etc/init.d/network restart
run /etc/init.d/firewall restart
run /etc/init.d/dnsmasq restart
run wifi reload

log "Configuring policy routing"
grep -q "$VPN_TABLE_ID $VPN_TABLE_NAME" /etc/iproute2/rt_tables || echo "$VPN_TABLE_ID $VPN_TABLE_NAME" >> /etc/iproute2/rt_tables
run ip route replace default dev "$WG_IF" table "$VPN_TABLE_NAME"
try ip rule del from "$VPNLAN_NETWORK" priority "$VPN_RULE_PRIORITY"
run ip rule add from "$VPNLAN_NETWORK" lookup "$VPN_TABLE_NAME" priority "$VPN_RULE_PRIORITY"

log "Setting up NAT masquerading"
iptables -t nat -C POSTROUTING -o "$WG_IF" -j MASQUERADE 2>/dev/null || \
  run iptables -t nat -A POSTROUTING -o "$WG_IF" -j MASQUERADE

log "Setting up killswitch"
ip rule add iif br-$VPNLAN not to $VPNLAN_NETWORK lookup main priority 101 || true
iptables -I FORWARD -i br-$VPNLAN -o eth0 -j DROP || true
ip6tables -I FORWARD -i br-$VPNLAN -o eth0 -j DROP || true

log "VPN Status"
try wg show "$WG_IF"
try ip route show table "$VPN_TABLE_NAME"
try ip rule

log "External connection test"
try curl -s https://ipinfo.io | grep -E 'ip|city|region|country'

log "✅ Setup complete. Clients on '$WIFI_SSID' SSID will use the VPN."
log "🔑 Wi-Fi password: $WIFI_PWD"
log "📍 Log file: $LOG"
