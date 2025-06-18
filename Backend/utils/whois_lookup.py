import whois
from datetime import datetime
from .output import print_info, print_error

def get_whois_info(host):
    print_info("Running Whois...")

    try:
        w = whois.whois(host)
        
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            creation_date = creation_date.strftime('%Y-%m-%d')
            
        expiry_date = w.expiration_date
        if isinstance(expiry_date, list):
            expiry_date = expiry_date[0]
        if expiry_date:
            expiry_date = expiry_date.strftime('%Y-%m-%d')
            
        # Handle name servers
        name_servers = w.name_servers
        if isinstance(name_servers, list):
            name_servers = name_servers[:2]
        else:
            name_servers = [name_servers] if name_servers else []
            
        return {
            "domain": host,
            "registrar": w.registrar or "Unknown",
            "creationDate": creation_date or "Unknown",
            "expiryDate": expiry_date or "Unknown",
            "nameServers": name_servers
        }
    except Exception as e:
        return {
            "domain": host,
            "registrar": "Unknown",
            "creationDate": "Unknown",
            "expiryDate": "Unknown",
            "nameServers": [],
            "error": str(e)
        }
