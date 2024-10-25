import requests
import os
import json
from dotenv import load_dotenv

# Define the path to your .env file
dotenv_path = os.path.join('./data', '.env')  # Adjust if necessary based on actual file structure
load_dotenv(dotenv_path=dotenv_path)

# Load Cloudflare API credentials
CF_API_EMAIL = os.getenv("CF_API_EMAIL")
CF_API_KEY = os.getenv("CF_API_KEY")
ZONE_INFO_FILE= os.getenv("ZONE_FILE_PATH")

def fetch_zone_info():
    """Fetch zone information from Cloudflare."""
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {CF_API_KEY}",
        "X-Auth-Email": CF_API_EMAIL,
    }
    response = requests.get("https://api.cloudflare.com/client/v4/zones", headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to fetch zone info: {response.status_code} - {response.text}")

def save_zone_info(data):
    """Save zone information to a JSON file, creating it if it doesn't exist."""
    file_path = './data/zoneinfo.json'
    with open(file_path, 'w') as file:
        json.dump(data, file, indent=4)

if __name__ == "__main__":
    try:
        zone_info = fetch_zone_info()
        save_zone_info(zone_info)
        print("Zone information successfully fetched and saved.")
    except Exception as e:
        print(f"An error occurred: {e}")