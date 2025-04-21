#!/bin/sh
# nordlynx-router.sh — Secure Split-Tunnel VPN (only 'NordVPN' SSID via VPN)
set -euo pipefail

readonly LOG="/tmp/nordlynx-router.log"
exec > >(tee -a "$LOG") 2>&1

# === Logging helpers ===
log() { printf "\033[1;34m==> %s\033[0m\n" "$@"; }
err() { printf "\033[1;31m❌ %s\033[0m\n" "$@" >&2; }
run() { log "+ $*"; "$@" || { err "FAILED: $*"; exit 1; }; }
try() { log "+ $* (ignore errors)"; "$@" || true; }

# === Constants ===
readonly CONF="/etc/wireguard/nordlynx.conf"
readonly WG_IF="wg0"
readonly VPNLAN_NETWORK="192.168.89.0/24"
readonly VPNLAN_IP="192.168.89.1"
readonly WIFI_SSID="NordVPN"
readonly WIFI_PWD="ChangeMe1234"
readonly VPN_TABLE_ID="100"
readonly VPN_TABLE_NAME="vpn"
readonly VPN_RULE_PRIORITY="100"

log "$(date) – NordVPN Split-Tunnel Setup Started"

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

log "Configuration loaded from $CONF"
log "VPN Address: $ADDRESS"
log "Endpoint: $ENDPOINT_HOST:$ENDPOINT_PORT"
log "PersistentKeepalive: $PERSIST"

log "Cleaning previous configuration..."
for item in \
  network."$WG_IF" network.nordvpn_peer network.vpnlan \
  dhcp.vpnlan wireless.nordvpn_ap \
  firewall.vpn_clients firewall.vpn_tunnel firewall.vpn_icmp
  do try uci delete "$item"; done

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

set network.nordvpn_peer='wireguard_$WG_IF'
set network.nordvpn_peer.public_key='$PUBKEY'
set network.nordvpn_peer.allowed_ips='0.0.0.0/0,::/0'
set network.nordvpn_peer.endpoint_host='$ENDPOINT_HOST'
set network.nordvpn_peer.endpoint_port='$ENDPOINT_PORT'
set network.nordvpn_peer.persistent_keepalive='$PERSIST'
set network.nordvpn_peer.description='NordVPN Server'
EOF
run uci commit network

log "Creating VPN LAN bridge interface"
uci batch <<EOF
set network.vpnlan='interface'
set network.vpnlan.type='bridge'
set network.vpnlan.proto='static'
set network.vpnlan.ipaddr='$VPNLAN_IP'
set network.vpnlan.netmask='255.255.255.0'
set network.vpnlan.force_link='1'
set network.vpnlan.delegate='0'
set network.vpnlan.peerdns='0'
set network.vpnlan.dns='$DNS1'
EOF
[ -n "$DNS2" ] && run uci add_list network.vpnlan.dns="$DNS2"
run uci commit network

log "Configuring DHCP for VPN LAN"
uci batch <<EOF
set dhcp.vpnlan='dhcp'
set dhcp.vpnlan.interface='vpnlan'
set dhcp.vpnlan.start='100'
set dhcp.vpnlan.limit='150'
set dhcp.vpnlan.leasetime='12h'
set dhcp.vpnlan.force='1'
set dhcp.vpnlan.dhcpv6='server'
set dhcp.vpnlan.ra='server'
EOF
run uci commit dhcp

# Add DNS options using list (avoid deprecation warning)
DNS_OPTION="6,$DNS1"
[ -n "$DNS2" ] && DNS_OPTION="$DNS_OPTION,$DNS2"
uci delete dhcp.vpnlan.dhcp_option 2>/dev/null || true
uci add_list dhcp.vpnlan.dhcp_option="$DNS_OPTION"
uci commit dhcp

log "Setting up VPN Wi-Fi AP: $WIFI_SSID"
RADIO=$(uci show wireless | grep '=wifi-device' | head -n1 | cut -d. -f2 | cut -d= -f1)
[ -n "$RADIO" ] || { err "No Wi-Fi radio found"; exit 1; }
try uci delete wireless.nordvpn_ap
uci batch <<EOF
set wireless.nordvpn_ap='wifi-iface'
set wireless.nordvpn_ap.device='$RADIO'
set wireless.nordvpn_ap.mode='ap'
set wireless.nordvpn_ap.network='vpnlan'
set wireless.nordvpn_ap.ssid='$WIFI_SSID'
set wireless.nordvpn_ap.encryption='sae-mixed'
set wireless.nordvpn_ap.key='$WIFI_PWD'
set wireless.nordvpn_ap.disabled='0'
set wireless.nordvpn_ap.isolate='1'
set wireless.nordvpn_ap.ieee80211w='1'
set wireless.nordvpn_ap.wps_pushbutton='0'
EOF
run uci commit wireless
run wifi reload

log "Configuring firewall zones"
uci batch <<EOF
set firewall.vpn_clients='zone'
set firewall.vpn_clients.name='vpn_clients'
set firewall.vpn_clients.network='vpnlan'
set firewall.vpn_clients.input='ACCEPT'
set firewall.vpn_clients.output='ACCEPT'
set firewall.vpn_clients.forward='REJECT'

set firewall.vpn_tunnel='zone'
set firewall.vpn_tunnel.name='vpn_tunnel'
set firewall.vpn_tunnel.network='$WG_IF'
set firewall.vpn_tunnel.input='REJECT'
set firewall.vpn_tunnel.output='ACCEPT'
set firewall.vpn_tunnel.forward='REJECT'
set firewall.vpn_tunnel.masq='1'
set firewall.vpn_tunnel.mtu_fix='1'

set firewall.vpn_forwarding='forwarding'
set firewall.vpn_forwarding.src='vpn_clients'
set firewall.vpn_forwarding.dest='vpn_tunnel'

set firewall.vpn_icmp='rule'
set firewall.vpn_icmp.name='Allow-ICMP-VPN'
set firewall.vpn_icmp.src='vpn_clients'
set firewall.vpn_icmp.proto='icmp'
set firewall.vpn_icmp.target='ACCEPT'
EOF
run uci commit firewall

log "Restarting services"
run /etc/init.d/network restart
run /etc/init.d/firewall restart
run /etc/init.d/dnsmasq restart
run wifi reload

log "Waiting for $WG_IF to be up..."
for i in $(seq 1 10); do ip link show "$WG_IF" >/dev/null 2>&1 && break; sleep 1; done
ip link show "$WG_IF" >/dev/null 2>&1 || { err "$WG_IF interface not found"; exit 1; }

# Wait for IP assignment to wg0
COUNT=0
until ip addr show dev "$WG_IF" | grep -q 'inet '; do
  sleep 1
  COUNT=$((COUNT + 1))
  [ "$COUNT" -gt 15 ] && err "$WG_IF did not receive an IP address" && exit 1
done

log "Configuring policy routing"
grep -q "$VPN_TABLE_ID $VPN_TABLE_NAME" /etc/iproute2/rt_tables || echo "$VPN_TABLE_ID $VPN_TABLE_NAME" >> /etc/iproute2/rt_tables
run ip route replace default dev "$WG_IF" table "$VPN_TABLE_NAME"
try ip rule del from "$VPNLAN_NETWORK" priority "$VPN_RULE_PRIORITY"
run ip rule add from "$VPNLAN_NETWORK" lookup "$VPN_TABLE_NAME" priority "$VPN_RULE_PRIORITY"

log "Setting up NAT masquerading for VPN"
for mod in nf_conntrack nf_nat xt_MASQUERADE ip_tables; do try modprobe "$mod"; done
iptables -t nat -C POSTROUTING -o "$WG_IF" -j MASQUERADE 2>/dev/null || \
  run iptables -t nat -A POSTROUTING -o "$WG_IF" -j MASQUERADE

log "Setting up killswitch"
ip rule add iif br-vpnlan not to $VPNLAN_NETWORK lookup main priority 101 || true
iptables -I FORWARD -i br-vpnlan -o eth0 -j DROP || true
ip6tables -I FORWARD -i br-vpnlan -o eth0 -j DROP || true

log "Creating hotplug VPN route checker"
cat > /etc/hotplug.d/iface/99-vpncheck << 'EOF'
#!/bin/sh
[ "$ACTION" = "ifup" ] && [ "$INTERFACE" = "wg0" ] && {
  ip route replace default dev wg0 table vpn
  ip rule del from 192.168.89.0/24 priority 100 2>/dev/null
  ip rule add from 192.168.89.0/24 lookup vpn priority 100
  iptables -t nat -C POSTROUTING -o wg0 -j MASQUERADE >/dev/null 2>&1 || \
    iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE
  logger -t vpncheck "WireGuard VPN route check completed"
}
EOF
chmod +x /etc/hotplug.d/iface/99-vpncheck

log "VPN Status"
try wg show
try ip route show table vpn
try ip rule

log "External connection test"
try curl -s https://ipinfo.io | grep -E 'ip|city|region|country'

log "✅ Setup complete. Clients on '$WIFI_SSID' SSID will use the VPN."
log "🔑 Wi-Fi password: $WIFI_PWD"
log "📍 Log file: $LOG"
