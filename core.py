#!/usr/bin/env python3
"""
Cloudflare Dynamic DNS Updater

Automatically updates Cloudflare DNS records with your current public IP address.
Simplified configuration - just specify the subdomains you want to update.
Supports both IPv4 (A) and IPv6 (AAAA) records.
"""

import requests
import os
import json
import sys
import logging
import logging.handlers
import socket
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from dotenv import load_dotenv
from typing import Optional, Dict, List, Tuple

# Try to import systemd journal logging (Linux only)
try:
    from systemd import journal
    SYSTEMD_AVAILABLE = True
except ImportError:
    SYSTEMD_AVAILABLE = False

# Constants
RECORD_TYPE_A = "A"
RECORD_TYPE_AAAA = "AAAA"
DEFAULT_RECORD_TYPES = [RECORD_TYPE_A, RECORD_TYPE_AAAA]


class CloudflareAPI:
    """A simplified Cloudflare API client for DNS record management."""
    
    BASE_URL = "https://api.cloudflare.com/client/v4"
    
    def __init__(self, api_email: str, api_key: str):
        """Initialize the Cloudflare API client."""
        self.api_email = api_email
        self.api_key = api_key
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "X-Auth-Email": api_email,
        }
        self._zones_cache: Optional[Dict[str, dict]] = None
    
    def _make_request(self, method: str, endpoint: str, **kwargs) -> dict:
        """Make an API request and handle errors."""
        url = f"{self.BASE_URL}{endpoint}"
        try:
            response = requests.request(method, url, headers=self.headers, **kwargs)
            response.raise_for_status()
            data = response.json()
            
            if not data.get("success", False):
                errors = data.get("errors", [])
                error_msg = "; ".join([e.get("message", str(e)) for e in errors])
                raise Exception(f"Cloudflare API error: {error_msg}")
            
            return data
        except requests.exceptions.RequestException as e:
            # Network/HTTP errors
            raise Exception(f"Request failed: {str(e)}")
        except Exception as e:
            # Catch all other exceptions, including the one raised when API returns success=false
            # Re-raise as-is if it's already our formatted exception
            if "Cloudflare API error" in str(e) or "Request failed" in str(e):
                raise
            # Wrap unexpected exceptions
            raise Exception(f"Unexpected error: {str(e)}")
    
    def get_zones(self, use_cache: bool = True) -> Dict[str, dict]:
        """Get all zones and cache them."""
        if use_cache and self._zones_cache is not None:
            return self._zones_cache
        
        data = self._make_request("GET", "/zones")
        zones = {}
        for zone in data.get("result", []):
            zones[zone["name"]] = {
                "id": zone["id"],
                "name": zone["name"],
                "status": zone.get("status"),
            }
        
        self._zones_cache = zones
        return zones
    
    def find_zone_for_domain(self, domain: str) -> Optional[dict]:
        """Find the zone for a given domain or subdomain."""
        zones = self.get_zones()
        
        # Try exact match first
        if domain in zones:
            return zones[domain]
        
        # Try to find parent zone
        parts = domain.split(".")
        for i in range(1, len(parts)):
            potential_zone = ".".join(parts[i:])
            if potential_zone in zones:
                return zones[potential_zone]
        
        return None
    
    def get_dns_records(self, zone_id: str, name: Optional[str] = None, record_type: Optional[str] = None) -> List[dict]:
        """Get DNS records for a zone, optionally filtered by name and type."""
        endpoint = f"/zones/{zone_id}/dns_records"
        params = {}
        if name:
            params["name"] = name
        if record_type:
            params["type"] = record_type
        
        data = self._make_request("GET", endpoint, params=params)
        return data.get("result", [])
    
    def find_dns_record(self, subdomain: str, record_type: str = RECORD_TYPE_A) -> Optional[dict]:
        """Find a DNS record by subdomain name and type."""
        zone = self.find_zone_for_domain(subdomain)
        if not zone:
            return None
        
        records = self.get_dns_records(zone["id"], name=subdomain, record_type=record_type)
        
        # Return the first matching record
        for record in records:
            if record["name"] == subdomain and record["type"] == record_type:
                return {
                    "id": record["id"],
                    "name": record["name"],
                    "type": record["type"],
                    "content": record.get("content"),
                    "zone_id": zone["id"],
                    "zone_name": zone["name"],
                }
        
        return None
    
    def update_dns_record(self, zone_id: str, record_id: str, name: str, content: str, 
                         record_type: str = RECORD_TYPE_A, ttl: int = 1, proxied: bool = False, 
                         comment: Optional[str] = None) -> dict:
        """Update a DNS record."""
        endpoint = f"/zones/{zone_id}/dns_records/{record_id}"
        
        # Comment should be provided by caller, but generate default if not
        if comment is None:
            comment = generate_update_comment()
        
        data = {
            "type": record_type,
            "name": name,
            "content": content,
            "ttl": ttl,
            "proxied": proxied,
            "comment": comment,
        }
        
        return self._make_request("PUT", endpoint, json=data)


def get_public_ipv4() -> str:
    """Get the current public IPv4 address."""
    services = [
        "https://ipv4.icanhazip.com",
        "https://ip.me",
    ]
    
    for service_url in services:
        try:
            response = requests.get(service_url, timeout=10)
            response.raise_for_status()
            ip = response.text.strip()
            # Basic validation
            parts = ip.split(".")
            if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                return ip
            # Invalid format, try next service
            continue
        except (requests.exceptions.RequestException, ValueError) as e:
            # Request failed or invalid format, try next service
            continue
        except Exception:
            # Unexpected error, try next service
            continue
    
    # All services failed
    raise Exception("Failed to get public IPv4 address from any service")


def get_public_ipv6() -> Optional[str]:
    """Get the current public IPv6 address."""
    services = [
        "https://ipv6.icanhazip.com",
        "https://api64.ipify.org?format=text",
    ]
    
    for service_url in services:
        try:
            response = requests.get(service_url, timeout=10)
            response.raise_for_status()
            ip = response.text.strip()
            # Validate IPv6 format
            try:
                socket.inet_pton(socket.AF_INET6, ip)
                return ip
            except socket.error:
                # Invalid IPv6 format, try next service
                continue
        except requests.exceptions.RequestException:
            # Service unavailable, try next one
            continue
        except Exception as e:
            # Unexpected error, try next service
            continue
    
    # All services failed
    return None


def get_public_ip() -> str:
    """Get the current public IPv4 address (backward compatibility)."""
    return get_public_ipv4()


def get_hostname() -> str:
    """Get the machine's hostname."""
    try:
        hostname = socket.gethostname()
        return hostname
    except Exception:
        return "unknown"


def generate_update_comment() -> str:
    """Generate a standardized comment for DNS record updates."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    hostname = get_hostname()
    return f"auto-updated by cloudflare-dynamic-dns on {timestamp} from {hostname}"


class Database:
    """SQLite database handler for storing IP addresses and update history."""
    
    def __init__(self, db_path: Path):
        """Initialize the database connection and create tables if needed."""
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()
    
    def _get_connection(self):
        """Get a database connection with proper error handling."""
        return sqlite3.connect(self.db_path)
    
    def _init_database(self):
        """Create database tables if they don't exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Table for storing last known IP addresses
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS last_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subdomain TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(subdomain, record_type)
                )
            ''')
            
            # Table for storing update history
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS update_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subdomain TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    old_ip TEXT,
                    new_ip TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    success INTEGER NOT NULL DEFAULT 1,
                    error_message TEXT
                )
            ''')
            
            # Create indexes for better query performance
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_last_ips_subdomain 
                ON last_ips(subdomain, record_type)
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_update_history_subdomain 
                ON update_history(subdomain, record_type, updated_at)
            ''')
            
            conn.commit()
    
    def get_last_ip(self, subdomain: str, record_type: str = RECORD_TYPE_A) -> Optional[str]:
        """Get the last known IP for a subdomain and record type."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT ip FROM last_ips 
                WHERE subdomain = ? AND record_type = ?
            ''', (subdomain, record_type))
            
            result = cursor.fetchone()
            return result[0] if result else None
    
    def save_last_ip(self, subdomain: str, ip: str, record_type: str = RECORD_TYPE_A) -> None:
        """Save the last known IP for a subdomain and record type."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO last_ips (subdomain, record_type, ip, updated_at)
                VALUES (?, ?, ?, ?)
            ''', (subdomain, record_type, ip, datetime.now(timezone.utc).isoformat()))
            
            conn.commit()
    
    def log_update(self, subdomain: str, record_type: str, old_ip: Optional[str], 
                   new_ip: str, success: bool = True, error_message: Optional[str] = None) -> None:
        """Log an update attempt to the history table."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO update_history 
                (subdomain, record_type, old_ip, new_ip, updated_at, success, error_message)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                subdomain, 
                record_type, 
                old_ip, 
                new_ip, 
                datetime.now(timezone.utc).isoformat(),
                1 if success else 0,
                error_message
            ))
            
            conn.commit()
    
    def get_update_history(self, subdomain: Optional[str] = None, 
                          record_type: Optional[str] = None, 
                          limit: int = 50) -> List[Dict]:
        """Get update history, optionally filtered by subdomain and/or record_type."""
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = 'SELECT * FROM update_history WHERE 1=1'
            params = []
            
            if subdomain:
                query += ' AND subdomain = ?'
                params.append(subdomain)
            
            if record_type:
                query += ' AND record_type = ?'
                params.append(record_type)
            
            query += ' ORDER BY updated_at DESC LIMIT ?'
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            return [dict(row) for row in rows]
    
    def get_statistics(self) -> Dict:
        """Get statistics about updates."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Total updates
            cursor.execute('SELECT COUNT(*) FROM update_history')
            total_updates = cursor.fetchone()[0]
            
            # Successful updates
            cursor.execute('SELECT COUNT(*) FROM update_history WHERE success = 1')
            successful_updates = cursor.fetchone()[0]
            
            # Failed updates
            cursor.execute('SELECT COUNT(*) FROM update_history WHERE success = 0')
            failed_updates = cursor.fetchone()[0]
            
            # Unique subdomains
            cursor.execute('SELECT COUNT(DISTINCT subdomain) FROM last_ips')
            unique_subdomains = cursor.fetchone()[0]
            
            # Last update time
            cursor.execute('SELECT MAX(updated_at) FROM update_history')
            last_update = cursor.fetchone()[0]
            
            return {
                'total_updates': total_updates,
                'successful_updates': successful_updates,
                'failed_updates': failed_updates,
                'unique_subdomains': unique_subdomains,
                'last_update': last_update
            }


def setup_logging(log_file: Optional[str] = None,
                  max_bytes: int = 10 * 1024 * 1024,
                  backup_count: int = 5) -> logging.Logger:
    """Setup logging to console, syslog, systemd journal, and optionally a rotating file."""
    logger = logging.getLogger('cloudflare-dynamic-dns')
    logger.setLevel(logging.INFO)

    # Clear any existing handlers
    logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # Rotating file handler (if configured)
    if log_file:
        try:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                log_path,
                maxBytes=max_bytes,
                backupCount=backup_count
            )
            file_handler.setLevel(logging.INFO)
            file_formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
            logger.info(f"Logging to file: {log_path} (max {max_bytes // 1024 // 1024}MB, {backup_count} backups)")
        except Exception as e:
            logger.warning(f"Could not setup file logging: {e}")

    # Try systemd journal (Linux)
    if SYSTEMD_AVAILABLE:
        try:
            journal_handler = journal.JournalHandler()
            journal_handler.setLevel(logging.INFO)
            logger.addHandler(journal_handler)
        except Exception as e:
            logger.debug(f"Could not setup systemd journal logging: {e}")

    # Try syslog (Unix-like systems)
    try:
        syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
        syslog_handler.setLevel(logging.INFO)
        syslog_formatter = logging.Formatter('cloudflare-dynamic-dns[%(process)d]: %(message)s')
        syslog_handler.setFormatter(syslog_formatter)
        logger.addHandler(syslog_handler)
    except Exception:
        # Try alternative syslog socket locations
        for socket_path in ['/var/run/syslog', '/var/run/log']:
            try:
                syslog_handler = logging.handlers.SysLogHandler(address=socket_path)
                syslog_handler.setLevel(logging.INFO)
                syslog_formatter = logging.Formatter('cloudflare-dynamic-dns[%(process)d]: %(message)s')
                syslog_handler.setFormatter(syslog_formatter)
                logger.addHandler(syslog_handler)
                break
            except Exception:
                continue

    return logger


def process_record(cf: CloudflareAPI, subdomain: str, record_type: str, current_ip: str, 
                   db: Database, logger: logging.Logger) -> Tuple[bool, bool]:
    """
    Process a single DNS record update.
    Returns: (success, updated)
    """
    old_ip = None
    try:
        # Find the DNS record
        record = cf.find_dns_record(subdomain, record_type=record_type)
        
        if not record:
            error_msg = f"DNS {record_type} record not found for {subdomain}"
            logger.warning(f"{error_msg}. Skipping.")
            db.log_update(subdomain, record_type, None, current_ip, success=False, 
                         error_message=error_msg)
            return False, False
        
        logger.info(f"Found {record_type} record: {record['name']} in zone {record['zone_name']}")
        logger.info(f"Current DNS value: {record['content']}")
        
        # Check if IP has changed
        last_ip = db.get_last_ip(subdomain, record_type)
        old_ip = record['content']
        
        if current_ip == record['content']:
            logger.info(f"✓ {record_type} IP is already up to date ({current_ip})")
            db.save_last_ip(subdomain, current_ip, record_type)
            # Log as successful check (no update needed)
            db.log_update(subdomain, record_type, old_ip, current_ip, success=True, 
                         error_message="No update needed - IP already matches DNS record")
            return True, False
        
        if current_ip == last_ip:
            logger.info(f"{record_type} IP hasn't changed since last check, but DNS record differs.")
            logger.info("Updating DNS record to match current IP...")
        else:
            logger.info(f"{record_type} IP changed from {last_ip or 'unknown'} to {current_ip}")
        
        # Generate timestamped comment with hostname
        comment = generate_update_comment()
        
        # Update the DNS record
        result = cf.update_dns_record(
            zone_id=record["zone_id"],
            record_id=record["id"],
            name=record["name"],
            content=current_ip,
            record_type=record["type"],
            comment=comment,
        )
        
        if result.get("success"):
            db.save_last_ip(subdomain, current_ip, record_type)
            db.log_update(subdomain, record_type, old_ip, current_ip, success=True)
            logger.info(f"✓ Successfully updated {subdomain} ({record_type}) to {current_ip}")
            return True, True
        else:
            error_msg = f"API returned success=false"
            db.log_update(subdomain, record_type, old_ip, current_ip, success=False, 
                         error_message=error_msg)
            logger.error(f"✗ Failed to update {subdomain} ({record_type})")
            return False, False
            
    except Exception as e:
        error_msg = str(e)
        db.log_update(subdomain, record_type, old_ip, current_ip, success=False, 
                     error_message=error_msg)
        logger.error(f"✗ Error processing {subdomain} ({record_type}): {e}")
        return False, False


def main():
    """Main function to update DNS records."""
    # Setup paths
    script_dir = Path(__file__).parent
    data_dir = script_dir / "data"

    # Load environment variables
    dotenv_path = data_dir / ".env"
    load_dotenv(dotenv_path=dotenv_path)

    # Setup logging (with optional file rotation from env)
    log_file = os.getenv("LOG_FILE")
    log_max_mb = int(os.getenv("LOG_MAX_MB", "10"))
    log_backup_count = int(os.getenv("LOG_BACKUP_COUNT", "5"))
    logger = setup_logging(
        log_file=log_file,
        max_bytes=log_max_mb * 1024 * 1024,
        backup_count=log_backup_count
    )

    # Get API credentials
    cf_api_email = os.getenv("CF_API_EMAIL")
    cf_api_key = os.getenv("CF_API_KEY")
    
    if not cf_api_email or not cf_api_key:
        logger.error("CF_API_EMAIL and CF_API_KEY must be set in ./data/.env")
        sys.exit(1)
    
    # Subdomains to update. Edit ./data/dnsrecords.txt or add entries here.
    # Format: "subdomain.domain.tld" or "subdomain.domain.tld:A" / ":AAAA"
    subdomains_config = [
        # "home.example.com",
        # "vpn.example.com:A",
    ]
    
    # You can also load from a file if preferred
    dns_records_file = data_dir / "dnsrecords.txt"
    if dns_records_file.exists():
        with open(dns_records_file) as f:
            file_subdomains = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            if file_subdomains:
                subdomains_config = file_subdomains
    
    if not subdomains_config:
        logger.error("No subdomains configured. Add entries to ./data/dnsrecords.txt")
        sys.exit(1)
    
    logger.info("Checking public IP and updating Cloudflare DNS...")
    
    # Initialize database
    db_path = data_dir / "cloudflare_dns.db"
    db = Database(db_path)
    logger.info(f"Using database: {db_path}")
    
    # Initialize API client
    cf = CloudflareAPI(cf_api_email, cf_api_key)
    
    # Get current public IPs
    try:
        current_ipv4 = get_public_ipv4()
        logger.info(f"Current public IPv4: {current_ipv4}")
    except Exception as e:
        logger.error(f"Error getting IPv4: {e}")
        current_ipv4 = None
    
    try:
        current_ipv6 = get_public_ipv6()
        if current_ipv6:
            logger.info(f"Current public IPv6: {current_ipv6}")
        else:
            logger.info("No IPv6 address detected")
    except Exception as e:
        logger.warning(f"Could not get IPv6: {e}")
        current_ipv6 = None
    
    if not current_ipv4 and not current_ipv6:
        logger.error("Could not determine any public IP address")
        sys.exit(1)
    
    # Process each subdomain
    updated_count = 0
    error_count = 0
    
    for subdomain_entry in subdomains_config:
        # Parse subdomain and record types
        if ":" in subdomain_entry:
            subdomain, record_types_str = subdomain_entry.split(":", 1)
            record_types = [rt.strip().upper() for rt in record_types_str.split(",")]
        else:
            subdomain = subdomain_entry
            record_types = DEFAULT_RECORD_TYPES  # Default to both
        
        logger.info(f"\nProcessing {subdomain}...")
        
        # Process A record
        if RECORD_TYPE_A in record_types:
            if current_ipv4:
                success, updated = process_record(cf, subdomain, RECORD_TYPE_A, current_ipv4, db, logger)
                if updated:
                    updated_count += 1
                if not success:
                    error_count += 1
            else:
                logger.warning("Skipping A record update - no IPv4 address available")
                # Don't count as error - IPv6-only setups are valid
        
        # Process AAAA record
        if RECORD_TYPE_AAAA in record_types:
            if current_ipv6:
                success, updated = process_record(cf, subdomain, RECORD_TYPE_AAAA, current_ipv6, db, logger)
                if updated:
                    updated_count += 1
                if not success:
                    error_count += 1
            else:
                logger.warning("Skipping AAAA record update - no IPv6 address available")
                # Don't count as error - IPv4-only setups are valid
    
    # Summary
    stats = db.get_statistics()
    logger.info(f"\n{'='*50}")
    logger.info(f"Summary: {updated_count} updated, {error_count} errors")
    logger.info(f"Database stats: {stats['total_updates']} total updates, "
                f"{stats['successful_updates']} successful, {stats['failed_updates']} failed")
    logger.info(f"{'='*50}")


if __name__ == "__main__":
    main()
