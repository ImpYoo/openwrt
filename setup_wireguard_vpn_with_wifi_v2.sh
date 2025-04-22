#!/bin/sh
# nordlynx-router.sh — Multi-WiFi Secure Split-Tunnel VPN with dynamic WireGuard configs
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 /etc/wireguard/yourname.conf" >&2
  exit 1
fi

CONF="$1"
NAME=$(basename "$CONF" .conf)
NAME_SHORT=$(echo "$NAME" | cut -d_ -f1)

readonly LOG="/tmp/nordlynx-router-${NAME_SHORT}.log"
exec > >(tee -a "$LOG") 2>&1

log() { printf "\033[1;34m==> %s\033[0m\n" "$@"; }
err() { printf "\033[1;31m❌ %s\033[0m\n" "$@" >&2; }
run() { log "+ $*"; "$@" || { err "FAILED: $*"; exit 1; }; }
try() { log "+ $* (ignore errors)"; "$@" || true; }

WG_IF="wg_${NAME_SHORT}"
VPNLAN="vpnlan_${NAME_SHORT}"
BR_DEV="br_${NAME_SHORT}"
VPNLAN_IP="192.168.$((RANDOM % 100 + 100)).1"
VPNLAN_NETWORK="${VPNLAN_IP%.*}.0/24"
WIFI_SSID="$NAME_SHORT"
WIFI_PWD="ChangeMe1234"
VPN_TABLE_ID=$((100 + $(echo "$NAME_SHORT" | md5sum | cut -c1-6 | tr -cd '0-9' | tail -c3)))
VPN_TABLE_NAME="$NAME_SHORT"
VPN_RULE_PRIORITY=100

log "$(date) – Setting up VPN for $NAME_SHORT from $CONF"

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
  network."$WG_IF" network.peer_${NAME_SHORT} network."$VPNLAN" \
  dhcp."$VPNLAN" wireless.ap_${NAME_SHORT} \
  firewall.clients_${NAME_SHORT} firewall.tunnel_${NAME_SHORT} firewall.icmp_${NAME_SHORT}; do
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

set network.peer_${NAME_SHORT}='wireguard_$WG_IF'
set network.peer_${NAME_SHORT}.public_key='$PUBKEY'
set network.peer_${NAME_SHORT}.allowed_ips='0.0.0.0/0,::/0'
set network.peer_${NAME_SHORT}.endpoint_host='$ENDPOINT_HOST'
set network.peer_${NAME_SHORT}.endpoint_port='$ENDPOINT_PORT'
set network.peer_${NAME_SHORT}.persistent_keepalive='$PERSIST'
set network.peer_${NAME_SHORT}.description='$NAME_SHORT'
EOF
run uci commit network
run /etc/init.d/network reload

log "Bringing up interface $WG_IF"
try modprobe wireguard || try modprobe wg

# Debug: show interfaces
ip link show | grep wg || true

run ifup "$WG_IF"

# If still not available, manually create the interface
if ! ip link show "$WG_IF" >/dev/null 2>&1; then
  log "$WG_IF not present, trying manual creation"
  ip link add dev "$WG_IF" type wireguard || true
  ip link set "$WG_IF" up || true
fi

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
set dhcp.$VPNLAN.ignore='0'
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
try uci delete wireless.ap_${NAME_SHORT}
uci batch <<EOF
set wireless.ap_${NAME_SHORT}='wifi-iface'
set wireless.ap_${NAME_SHORT}.device='$RADIO'
set wireless.ap_${NAME_SHORT}.mode='ap'
set wireless.ap_${NAME_SHORT}.network='$VPNLAN'
set wireless.ap_${NAME_SHORT}.ssid='$WIFI_SSID'
set wireless.ap_${NAME_SHORT}.encryption='sae-mixed'
set wireless.ap_${NAME_SHORT}.key='$WIFI_PWD'
set wireless.ap_${NAME_SHORT}.disabled='0'
set wireless.ap_${NAME_SHORT}.isolate='1'
set wireless.ap_${NAME_SHORT}.ieee80211w='1'
set wireless.ap_${NAME_SHORT}.wps_pushbutton='0'
EOF
run uci commit wireless
run wifi reload

log "Configuring firewall zones"
uci batch <<EOF
set firewall.clients_${NAME_SHORT}='zone'
set firewall.clients_${NAME_SHORT}.name='clients_${NAME_SHORT}'
set firewall.clients_${NAME_SHORT}.network='$VPNLAN'
set firewall.clients_${NAME_SHORT}.input='ACCEPT'
set firewall.clients_${NAME_SHORT}.output='ACCEPT'
set firewall.clients_${NAME_SHORT}.forward='ACCEPT'

set firewall.tunnel_${NAME_SHORT}='zone'
set firewall.tunnel_${NAME_SHORT}.name='tunnel_${NAME_SHORT}'
set firewall.tunnel_${NAME_SHORT}.network='$WG_IF'
set firewall.tunnel_${NAME_SHORT}.input='REJECT'
set firewall.tunnel_${NAME_SHORT}.output='ACCEPT'
set firewall.tunnel_${NAME_SHORT}.forward='REJECT'
set firewall.tunnel_${NAME_SHORT}.masq='1'
set firewall.tunnel_${NAME_SHORT}.mtu_fix='1'

set firewall.forward_${NAME_SHORT}='forwarding'
set firewall.forward_${NAME_SHORT}.src='clients_${NAME_SHORT}'
set firewall.forward_${NAME_SHORT}.dest='tunnel_${NAME_SHORT}'

set firewall.icmp_${NAME_SHORT}='rule'
set firewall.icmp_${NAME_SHORT}.name='Allow-ICMP-${NAME_SHORT}'
set firewall.icmp_${NAME_SHORT}.src='clients_${NAME_SHORT}'
set firewall.icmp_${NAME_SHORT}.proto='icmp'
set firewall.icmp_${NAME_SHORT}.target='ACCEPT'
EOF
run uci commit firewall

log "Restarting services"
run /etc/init.d/network restart
run /etc/init.d/firewall restart
run /etc/init.d/dnsmasq restart
run wifi reload

log "Waiting for $WG_IF to stabilize..."
COUNT=0
until ip link show "$WG_IF" | grep -q "LOWER_UP"; do
  sleep 1
  COUNT=$((COUNT + 1))
  [ "$COUNT" -gt 10 ] && err "$WG_IF is up but not ready for routing" && exit 1
done

log "Configuring policy routing"
grep -q "$VPN_TABLE_ID $VPN_TABLE_NAME" /etc/iproute2/rt_tables || echo "$VPN_TABLE_ID $VPN_TABLE_NAME" >> /etc/iproute2/rt_tables
run ip route replace default dev "$WG_IF" table "$VPN_TABLE_NAME"
try ip rule del from "$VPNLAN_NETWORK" priority "$VPN_RULE_PRIORITY"
run ip rule add from "$VPNLAN_NETWORK" lookup "$VPN_TABLE_NAME" priority "$VPN_RULE_PRIORITY"

log "Setting up NAT masquerading"
iptables -t nat -C POSTROUTING -o "$WG_IF" -j MASQUERADE 2>/dev/null || \
  run iptables -t nat -A POSTROUTING -o "$WG_IF" -j MASQUERADE

log "Setting up killswitch"
ip rule add iif $BR_DEV not to $VPNLAN_NETWORK lookup main priority 101 || true
iptables -I FORWARD -i $BR_DEV -o eth0 -j DROP || true
ip6tables -I FORWARD -i $BR_DEV -o eth0 -j DROP || true

log "VPN Status"
try wg show "$WG_IF"
try ip route show table "$VPN_TABLE_NAME"
try ip rule

log "External connection test"
try curl -s https://ipinfo.io | grep -E 'ip|city|region|country'

log "✅ Setup complete. Clients on '$WIFI_SSID' SSID will use the VPN."
log "🔑 Wi-Fi password: $WIFI_PWD"
log "📍 Log file: $LOG"
