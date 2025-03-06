import requests
import json

class Cloudflare:
    def get_zones():
        """
        curl -X GET  --url https://api.cloudflare.com/client/v4/zones \
            -H "Content-Type: application/json" -H "Authorization: Bearer ${CF_API_KEY}" -H "X-Auth-Email: ${CF_API_EMAIL}"
        """
        requests.get("https://api.cloudflare.com/client/v4/zones", headers={
            "X-Auth-Key": api_key,
            "X-Auth-Email": api_email,
        })


    def update_dns(zone_id, subdomain, record_type, record_id, public_ip):
        """
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
        """
        # validate url components
        requests.put(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}",
            headers={
                "X-Auth-Key": api_key,
                "X-Auth-Email": api_email,
            }, json={
                "type": record_type,
                "comment": "auto-updated by code in homelab on docker lxc",
                "name": subdomain,
                "content": public_ip,
                "ttl": 1,
                "proxied": False
            })
