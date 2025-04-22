#!/bin/sh
# Simple NordVPN WireGuard config generator for OpenWrt
# Usage: ./create_nordvpn_wireguard_config.sh [COUNTRY_CODE]

COUNTRY_ID=228
COUNTRY_CODE="US"
PRIVATE_KEY="" 

# Static IP address and DNS settings (replace with your actual values if needed)
IP_ADDRESS="10.5.0.2/32"
DNS_SERVERS="103.86.96.100, 103.86.99.100"

# Check for country code argument
if [ $# -eq 1 ]; then
  COUNTRY_CODE=$(echo "$1" | tr 'a-z' 'A-Z')
  
  # Get country ID from code if provided
  echo "Looking up country ID for $COUNTRY_CODE..."
  LOOKUP=$(curl -s "https://api.nordvpn.com/v1/servers/countries" | grep -o "\"id\":[0-9]*,\"name\":\"[^\"]*\",\"code\":\"$COUNTRY_CODE\"")
  
  if [ -n "$LOOKUP" ]; then
    COUNTRY_ID=$(echo "$LOOKUP" | grep -o "\"id\":[0-9]*" | grep -o "[0-9]*")
    echo "Found country ID: $COUNTRY_ID"
  else
    echo "Error: Invalid country code. Using default (US)."
    COUNTRY_ID=228
    COUNTRY_CODE="US"
  fi
fi

echo "Fetching recommended NordVPN server in $COUNTRY_CODE (ID: $COUNTRY_ID)..."

# Get server data - using grep since we can't rely on jq
SERVER_DATA=$(curl -s "https://api.nordvpn.com/v1/servers/recommendations?filters\[servers_technologies\]\[identifier\]=wireguard_udp&filters\[country_id\]=$COUNTRY_ID&limit=1")

if [ -z "$SERVER_DATA" ] || [ "$SERVER_DATA" = "[]" ]; then
  echo "Error: Failed to get server recommendations or no servers available."
  exit 1
fi

# Save JSON to temporary file for easier processing
TMP_FILE="/tmp/nordvpn_server.json"
echo "$SERVER_DATA" > "$TMP_FILE"

# Extract server information using grep and sed
HOSTNAME=$(grep -o '"hostname":"[^"]*"' "$TMP_FILE" | head -1 | sed 's/"hostname":"//;s/"//')
SERVER_IP=$(grep -o '"station":"[^"]*"' "$TMP_FILE" | head -1 | sed 's/"station":"//;s/"//')

# Extract subdomain from hostname (e.g., "de1135" from "de1135.nordvpn.com")
SERVER_SUBDOMAIN=$(echo "$HOSTNAME" | cut -d. -f1)

# Extract location information
CITY=$(grep -o '"city":{"id":[^}]*,"name":"[^"]*"' "$TMP_FILE" | grep -o '"name":"[^"]*"' | head -1 | sed 's/"name":"//;s/"//')
COUNTRY=$(grep -o '"country":{"id":[^,]*,"name":"[^"]*"' "$TMP_FILE" | grep -o '"name":"[^"]*"' | head -1 | sed 's/"name":"//;s/"//')

# Extract load
LOAD=$(grep -o '"load":[0-9]*' "$TMP_FILE" | grep -o '[0-9]*' | head -1)

# Extract WireGuard specific data
# First find the WireGuard technology section
WIREGUARD_SECTION=$(sed -n '/"identifier":"wireguard_udp"/,/},/p' "$TMP_FILE")

# Extract public key from WireGuard section
PUBLIC_KEY=$(echo "$WIREGUARD_SECTION" | grep -o '"name":"public_key","value":"[^"]*"' | sed 's/"name":"public_key","value":"//;s/"//')

# Look for NordWhisper section to find port (since WireGuard doesn't explicitly list port)
NORDWHISPER_SECTION=$(sed -n '/"identifier":"nordwhisper"/,/},/p' "$TMP_FILE")
#PORT=$(echo "$NORDWHISPER_SECTION" | grep -o '"name":"port","value":"[^"]*"' | sed 's/"name":"port","value":"//;s/"//')

# If no port found, use default 51820
if [ -z "$PORT" ]; then
  PORT="51820"
fi

# Show extracted information
echo "Selected server: $HOSTNAME ($SERVER_IP)"
echo "Location: $CITY, $COUNTRY"
echo "Load: $LOAD%"
echo "Port: $PORT"
echo "Public Key: $PUBLIC_KEY"

# Check if we got all necessary information
if [ -z "$PUBLIC_KEY" ]; then
  echo "Error: Could not extract public key. Check the API response format."
  exit 1
fi

if [ -z "$SERVER_IP" ]; then
  echo "Error: Could not extract server IP. Check the API response format."
  exit 1
fi

# Generate filename from server subdomain and city
# Replace spaces with underscores in city name
CITY_CLEAN=$(echo "$CITY" | tr ' ' '_')
if [ -z "$CITY_CLEAN" ]; then
  # If city is empty, use country instead
  CITY_CLEAN=$(echo "$COUNTRY" | tr ' ' '_')
fi

CONFIG_FILENAME="${SERVER_SUBDOMAIN}_${CITY_CLEAN}.conf"
CONFIG_FILE="/etc/wireguard/$CONFIG_FILENAME"

echo "Creating WireGuard configuration file: $CONFIG_FILE"

cat > "$CONFIG_FILE" << EOL
[Interface]
PrivateKey = $PRIVATE_KEY
Address = $IP_ADDRESS
DNS = $DNS_SERVERS

[Peer]
PublicKey = $PUBLIC_KEY
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $SERVER_IP:$PORT
PersistentKeepalive = 25
EOL

chmod 600 "$CONFIG_FILE"

echo "Configuration saved to $CONFIG_FILE"
echo
echo "To use this configuration with WireGuard, run:"
echo "  /etc/init.d/wireguard restart"
echo "Or if using wg-quick:"
echo "  wg-quick up ${CONFIG_FILENAME%.conf}"
echo

# Clean up temp file
rm -f "$TMP_FILE"

# Create symlink for nordlynx.conf for easy reference
ln -sf "$CONFIG_FILE" /etc/wireguard/nordlynx.conf

# Optional: Generate an updated script with the new server
UPDATED_SCRIPT="/root/nordvpn_update_server.sh"
echo "Creating server update script: $UPDATED_SCRIPT"

cat > "$UPDATED_SCRIPT" << EOL
#!/bin/sh
# Update NordVPN WireGuard configuration with new server

# Stop WireGuard
/etc/init.d/wireguard stop

# Update configuration file
cat > "$CONFIG_FILE" << 'EOFINNER'
[Interface]
PrivateKey = $PRIVATE_KEY
Address = $IP_ADDRESS
DNS = $DNS_SERVERS

[Peer]
PublicKey = $PUBLIC_KEY
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $SERVER_IP:$PORT
PersistentKeepalive = 25
EOFINNER

# Update symlink
ln -sf "$CONFIG_FILE" /etc/wireguard/nordlynx.conf

# Start WireGuard
/etc/init.d/wireguard start

echo "Updated to server: $HOSTNAME"
echo "IP: $SERVER_IP"
echo "Location: $CITY, $COUNTRY"
echo "Load: $LOAD%"
EOL

chmod +x "$UPDATED_SCRIPT"
echo "You can update this server configuration later by running: $UPDATED_SCRIPT"
