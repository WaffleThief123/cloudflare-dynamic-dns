# Cloudflare Dynamic DNS

A Python script that keeps your Cloudflare DNS records updated with your current public IP. Useful for home servers, self-hosted services, or anywhere you need DNS to track a changing IP address.

## Features

- **Automatic discovery** - Finds zones and records on its own; no need to look up IDs manually
- **IPv4 and IPv6** - Updates both A and AAAA records
- **Change detection** - Only pushes updates when your IP actually changes
- **History tracking** - SQLite database logs all updates with timestamps
- **Systemd integration** - Logs to the journal and syslog for easy monitoring
- **Multiple subdomains** - Update as many records as you need in a single run

## Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure API Credentials

Create `./data/.env` with your Cloudflare credentials:

```bash
CF_API_EMAIL=your-email@example.com
CF_API_KEY=your-api-token-here
```

**Getting an API token:**

1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com) → **My Profile** → **API Tokens**
2. Click **Create Token** and use the "Edit zone DNS" template
3. Set permissions to `Zone` → `DNS` → `Edit`
4. Copy the token into your `.env` file

You can also use a Global API Key instead of a token, but tokens are more secure since they can be scoped to specific permissions.

### 3. Configure Subdomains

Add the subdomains you want to update to `./data/dnsrecords.txt`, one per line:

```
home.example.com
vpn.example.com:A
server.example.com:AAAA
```

By default, both A (IPv4) and AAAA (IPv6) records are updated. Append `:A` or `:AAAA` to limit it to one type.

Alternatively, you can edit the `subdomains_config` list in `core.py` directly.

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

1. Detects your current public IPv4 and IPv6 addresses
2. For each subdomain, finds the matching Cloudflare zone and DNS record
3. Compares the current IP with what's in DNS
4. Updates the record if they differ, adding a timestamp to the record comment
5. Logs everything to a local SQLite database and the system journal

## Database

All state is stored in `./data/cloudflare_dns.db`. The database tracks:

- **last_ips** - Current IP for each subdomain/record type
- **update_history** - Full log of every update attempt

Some useful queries:

```bash
# Recent updates
sqlite3 ./data/cloudflare_dns.db "SELECT * FROM update_history ORDER BY updated_at DESC LIMIT 10;"

# Failed updates only
sqlite3 ./data/cloudflare_dns.db "SELECT * FROM update_history WHERE success = 0;"
```

The database is created automatically on first run.

## Logging

Output goes to stdout, syslog, and the systemd journal (if available). View logs with:

```bash
journalctl -u cloudflare-dns.service -f
```

## IPv6 Support

If you have a public IPv6 address, it will be detected and used for AAAA records. If not, AAAA updates are skipped silently and A records are still processed.

## Requirements

- Python 3.6+
- `requests`
- `python-dotenv`
- `systemd` (optional, for journal logging)

## Troubleshooting

**"DNS record not found"** - The subdomain must already exist in Cloudflare. This script updates records, it doesn't create them.

**"Failed to get public IP"** - Check your internet connection. The IP lookup services may also be temporarily down.

**"Cloudflare API error"** - Double-check your credentials and make sure your token has DNS:Edit permissions for the zone.

## License

See LICENSE file for details.
