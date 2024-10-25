#!/usr/bin/env python3
import requests
import os
from dotenv import load_dotenv

# Load environment variables from .env file in the ./data/ directory
dotenv_path = os.path.join('./data', '.env')
load_dotenv(dotenv_path=dotenv_path)

# Cloudflare API credentials
CF_API_EMAIL = os.getenv("CF_API_EMAIL")
CF_API_KEY = os.getenv("CF_API_KEY")

# Dictionary of Cloudflare zones and corresponding subdomains
# Format: {"subdomain.domain.tld": "ZONE_ID:RECORD_TYPE:RECORD_ID"}
zones_subdomains = {
    "subdomain.domain.tld": "example-zone-id:example-record-type:example-record-id",
    # Add more entries as needed
}

def get_public_ip():
    """Function to get the current public IP."""
    response = requests.get("https://ip.me")
    return response.text

def update_cloudflare_dns(cf_zone_id, subdomain, cf_record_type, cf_record_id, current_public_ip):
    """Function to update Cloudflare DNS record."""
    url = f"https://api.cloudflare.com/client/v4/zones/{cf_zone_id}/dns_records/{cf_record_id}"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {CF_API_KEY}",
        "X-Auth-Email": CF_API_EMAIL,
    }
    data = {
        "type": cf_record_type,
        "name": subdomain,
        "content": current_public_ip,
        "ttl": 1,
        "proxied": False,
        "comment": "auto-updated by code in homelab on docker lxc",
    }
    response = requests.put(url, headers=headers, json=data)
    return response.json()

def get_cloudflare_zones():
    """Function to get Cloudflare zones."""
    url = "https://api.cloudflare.com/client/v4/zones"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {CF_API_KEY}",
        "X-Auth-Email": CF_API_EMAIL,
    }
    response = requests.get(url, headers=headers)
    return response.json()

print("Checking public IP and updating Cloudflare DNS...")

# Get current public IP
current_ip = get_public_ip()

# Iterate through zones for subdomain and records
for subdomain, entry in zones_subdomains.items():
    cf_zone_id, record_type, cf_record_id = entry.split(':')

    # Read the last known IP from file (if exists) or default to an empty string
    try:
        with open(f"last_ip_{subdomain}.txt", "r") as file:
            last_ip = file.read().strip()
    except FileNotFoundError:
        last_ip = ""

    # Update Cloudflare DNS if the IP has changed
    if current_ip != last_ip:
        update_cloudflare_dns(cf_zone_id, subdomain, record_type, cf_record_id, current_ip)
        with open(f"last_ip_{subdomain}.txt", "w") as file:
            file.write(current_ip)
        print(f"Updated DNS record for {subdomain} to {current_ip} with custom string {cf_record_id}")
    else:
        print(f"Public IP has not changed for {subdomain}.")

