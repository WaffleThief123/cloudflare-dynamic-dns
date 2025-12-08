# Cloudflare Dynamic DNS

A Python tool that automatically updates Cloudflare DNS records with your current public IP address. This is a simplified, user-friendly version of the original bash script.

## Features

- **Automatic Discovery**: Automatically finds zones and DNS records - no need to manually look up zone IDs or record IDs
- **IPv4 & IPv6 Support**: Automatically detects and updates both A (IPv4) and AAAA (IPv6) records
- **SQLite Database**: Stores all data in a SQLite database for reliable tracking and history
- **Update History**: Complete audit trail of all update attempts with timestamps and success/failure status
- **Simple Configuration**: Just list the subdomains you want to update
- **IP Change Detection**: Only updates DNS when your IP address changes
- **Timestamped Updates**: Adds timestamps to Cloudflare record comments showing when each record was last updated
- **System Logging**: Logs to syslog and systemd journal (when available) for easy monitoring
- **Error Handling**: Comprehensive error handling and logging
- **Multiple Subdomains**: Update multiple DNS records in a single run

## Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure API Credentials

Create a `.env` file in the `./data/` directory with your Cloudflare API credentials.

**Example `.env` file:**

```bash
# Cloudflare API Credentials
# Required: Your Cloudflare account email address
CF_API_EMAIL=your-email@example.com

# Required: Your Cloudflare API key or token
# Option 1: Global API Key (found in My Profile → API Tokens)
CF_API_KEY=your-global-api-key-here

# Option 2: API Token (recommended for better security)
# Create a token with DNS:Edit permissions at:
# https://dash.cloudflare.com/profile/api-tokens
# CF_API_KEY=your-api-token-here
```

**Getting your Cloudflare API credentials:**

1. **Using Global API Key (simpler, less secure):**
   - Log in to [Cloudflare Dashboard](https://dash.cloudflare.com)
   - Go to **My Profile** → **API Tokens**
   - Scroll down to **API Keys** section
   - Click **View** next to "Global API Key"
   - Copy the key and paste it as `CF_API_KEY` in your `.env` file

2. **Using API Token (recommended, more secure):**
   - Log in to [Cloudflare Dashboard](https://dash.cloudflare.com)
   - Go to **My Profile** → **API Tokens**
   - Click **Create Token**
   - Use the "Edit zone DNS" template or create a custom token with:
     - **Permissions**: `Zone` → `DNS` → `Edit`
     - **Zone Resources**: Include → All zones (or specific zones)
   - Copy the token and paste it as `CF_API_KEY` in your `.env` file

**Security Notes:**
- Never commit your `.env` file to version control
- The `.env` file is already in `.gitignore` (if using git)
- API Tokens are preferred over Global API Keys as they can be scoped to specific permissions
- Keep your API credentials secure and rotate them periodically

### 3. Configure Subdomains

You have two options:

**Option A: Edit `core.py`**
```python
subdomains_config = [
    "home.example.com",  # Will update both A and AAAA records if available
    "vpn.example.com:A",  # Only update A (IPv4) record
    "server.example.com:AAAA",  # Only update AAAA (IPv6) record
    "api.example.com:A,AAAA",  # Explicitly update both
    # Add more entries as needed
]
```

**Option B: Use `./data/dnsrecords.txt`**
Create or edit `./data/dnsrecords.txt` with one subdomain per line:
```
home.example.com
vpn.example.com:A
server.example.com:AAAA
api.example.com:A,AAAA
```

**Record Type Options:**
- `subdomain.example.com` - Updates both A and AAAA records (default)
- `subdomain.example.com:A` - Only updates A (IPv4) record
- `subdomain.example.com:AAAA` - Only updates AAAA (IPv6) record
- `subdomain.example.com:A,AAAA` - Explicitly updates both record types

## Usage

### Manual Execution

```bash
python3 core.py
```

### Systemd Service

Create a systemd service file (e.g., `/etc/systemd/system/cloudflare-dns.service`):

```ini
[Unit]
Description=Cloudflare Dynamic DNS Updater
After=network.target

[Service]
Type=oneshot
User=your-username
WorkingDirectory=/path/to/cloudflare-dynamic-dns
ExecStart=/usr/bin/python3 /path/to/cloudflare-dynamic-dns/core.py
Environment="PATH=/usr/bin:/usr/local/bin"

[Install]
WantedBy=multi-user.target
```

Create a timer to run it periodically (e.g., `/etc/systemd/system/cloudflare-dns.timer`):

```ini
[Unit]
Description=Run Cloudflare DNS updater every 5 minutes
Requires=cloudflare-dns.service

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
```

Enable and start the timer:
```bash
sudo systemctl enable cloudflare-dns.timer
sudo systemctl start cloudflare-dns.timer
```

## How It Works

1. The script automatically detects your current public IPv4 and IPv6 addresses
2. For each configured subdomain:
   - Automatically finds the Cloudflare zone
   - Locates the DNS A and/or AAAA records (based on configuration)
   - Compares the current IP with the DNS record value
   - Updates the record if the IP has changed
   - Adds a timestamped comment to the Cloudflare record showing when it was updated
3. Stores all data in a SQLite database (`./data/cloudflare_dns.db`):
   - Last known IP addresses for each subdomain/record type
   - Complete update history with timestamps
   - Success/failure tracking
4. Logs all activities to syslog/systemd journal for monitoring

## Database

The script uses SQLite to store data in `./data/cloudflare_dns.db`. The database includes:

### Tables

- **last_ips**: Stores the last known IP address for each subdomain and record type
  - `subdomain`: The subdomain name
  - `record_type`: A or AAAA
  - `ip`: The last known IP address
  - `updated_at`: Timestamp of last update

- **update_history**: Complete history of all update attempts
  - `subdomain`: The subdomain name
  - `record_type`: A or AAAA
  - `old_ip`: Previous IP address (if known)
  - `new_ip`: New IP address
  - `updated_at`: Timestamp of the update
  - `success`: Whether the update was successful (1 or 0)
  - `error_message`: Error message if the update failed

### Querying the Database

You can query the database using any SQLite client:

```bash
# View last known IPs
sqlite3 ./data/cloudflare_dns.db "SELECT * FROM last_ips;"

# View recent update history
sqlite3 ./data/cloudflare_dns.db "SELECT * FROM update_history ORDER BY updated_at DESC LIMIT 10;"

# View failed updates
sqlite3 ./data/cloudflare_dns.db "SELECT * FROM update_history WHERE success = 0;"

# Get statistics
sqlite3 ./data/cloudflare_dns.db "SELECT COUNT(*) as total, SUM(success) as successful, SUM(1-success) as failed FROM update_history;"
```

The database is automatically created on first run and requires no additional configuration.

## Logging

The script automatically logs to:
- **Console/STDOUT**: Human-readable output
- **Syslog**: Available on Unix-like systems (Linux, macOS, etc.)
- **Systemd Journal**: Available on systemd-based Linux systems (if `systemd` Python package is installed)

View logs with:
```bash
# Systemd journal
journalctl -u cloudflare-dns.service -f

# Syslog (varies by system)
tail -f /var/log/syslog | grep cloudflare-dynamic-dns
# or
tail -f /var/log/messages | grep cloudflare-dynamic-dns
```

## IPv6 Support

The script automatically detects your public IPv6 address if available. If IPv6 is not available, the script will:
- Skip AAAA record updates for that subdomain
- Log a warning message
- Continue processing other records

IPv6 detection uses multiple services for reliability:
- Primary: `ipv6.icanhazip.com`
- Fallback: `api64.ipify.org`

## Requirements

- Python 3.6+
- `requests` library
- `python-dotenv` library
- `systemd` library (optional, for systemd journal logging on Linux)
- `sqlite3` (included with Python standard library)

See `requirements.txt` for details.

**Optional:** For systemd journal logging on Linux systems:
```bash
pip install systemd
```

## Troubleshooting

### "DNS record not found"
- Make sure the subdomain exists in Cloudflare
- Verify the subdomain is spelled correctly
- Ensure you have the correct API permissions

### "Failed to get public IP"
- Check your internet connection
- The IP service (ip.me) might be temporarily unavailable

### "Cloudflare API error"
- Verify your API credentials are correct
- Check that your API token has DNS:Edit permissions
- Ensure the subdomain belongs to a zone in your Cloudflare account

## License

See LICENSE file for details.
