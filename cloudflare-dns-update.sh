#!/usr/bin/env bash

# Cloudflare API credentials
CF_API_EMAIL="example@foo.xyz"
CF_API_KEY="example_api_key"

# Array of Cloudflare zones and corresponding subdomains
# Format: (ZONE_ID SUBDOMAIN RECORD_TYPE)
# Declare an associative array of Cloudflare zones and corresponding subdomains
declare -A ZONES_SUBDOMAINS=(
    ["subdomain.domain.tld"]="example-api-response"
    # Add more entries as needed
)

# Function to get the current public IP
get_public_ip() {
    curl -s https://ip.me
}

# Function to update Cloudflare DNS record
update_cloudflare_dns() {
    local CF_ZONE_ID="$1"
    local SUBDOMAIN="$2"
    local CF_RECORD_TYPE="$3"
    local CF_RECORD_ID="$4"
    local CURRENT_PUBLIC_IP="$5"

    curl -X PUT "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records/$CF_RECORD_ID" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $CF_API_KEY" \
        -H "X-Auth-Email: $CF_API_EMAIL" \
        --data '{
            "type": "'"$CF_RECORD_TYPE"'",
            "comment": "auto-updated by code in homelab on docker lxc",
            "name": "'"$SUBDOMAIN"'",
            "content": "'"$CURRENT_PUBLIC_IP"'",
            "ttl": 1,
            "proxied": false
        }'
}

get_cloudflare_zones () {
    curl -X GET  --url https://api.cloudflare.com/client/v4/zones \
        -H "Content-Type: application/json" -H "Authorization: Bearer ${CF_API_KEY}" -H "X-Auth-Email: ${CF_API_EMAIL}"
}

echo "Checking public IP and updating Cloudflare DNS..."

# Get current public IP
current_ip=$(get_public_ip)

# Iterate through zones for subdomain and strings
for subdomain in "${!ZONES_SUBDOMAINS[@]}"; do
    entry="${ZONES_SUBDOMAINS[$subdomain]}"
    IFS=':' read -r -a entry_parts <<< "$entry"
    CF_ZONE_ID="${entry_parts[0]}"
    RECORD_TYPE="${entry_parts[1]}"
    CF_RECORD_ID="${entry_parts[2]}"

    # Update Cloudflare DNS if the IP has changed
    if [ "$current_ip" != "$(cat "last_ip_$subdomain.txt" 2>/dev/null)" ]; then
        update_cloudflare_dns "$CF_ZONE_ID" "$subdomain" "$RECORD_TYPE" "$CF_RECORD_ID" "$current_ip"
        echo "$current_ip" > "last_ip_$subdomain.txt"
        echo "Updated DNS record for $subdomain to $current_ip with custom string $CF_RECORD_ID"
    else
        echo "Public IP has not changed for $subdomain."
    fi
done
