import whois

def get_whois_info(host):
    try:
        w = whois.whois(host)
        
        # Handle creation date
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date and hasattr(creation_date, 'strftime'):
            creation_date = creation_date.strftime('%Y-%m-%d')
        else:
            creation_date = "Unknown"
        
        # Handle expiry date
        expiry_date = w.expiration_date
        if isinstance(expiry_date, list):
            expiry_date = expiry_date[0]
        if expiry_date and hasattr(expiry_date, 'strftime'):
            expiry_date = expiry_date.strftime('%Y-%m-%d')
        else:
            expiry_date = "Unknown"
        
        # Handle name servers
        name_servers = w.name_servers
        if isinstance(name_servers, list):
            name_servers = name_servers[:2]
        elif name_servers:
            name_servers = [name_servers]
        else:
            name_servers = []
        
        # Try to extract hosting provider from WHOIS fields
        hosting_provider = (
            getattr(w, 'org', None) or
            getattr(w, 'organization', None) or
            getattr(w, 'netname', None)
        )
        if isinstance(hosting_provider, list):
            hosting_provider = hosting_provider[0] if hosting_provider else None
        if not hosting_provider:
            hosting_provider = "Unknown"
        
        return {
            "domain": host,
            "registrar": w.registrar or "Unknown",
            "creationDate": creation_date,
            "expiryDate": expiry_date,
            "nameServers": name_servers,
            "hostingProvider": hosting_provider
        }

    except Exception as e:
        print(f"Error fetching WHOIS data for {host}: {e}")
        return {
            "domain": host,
            "registrar": "Unknown",
            "creationDate": "Unknown",
            "expiryDate": "Unknown",
            "nameServers": [],
            "hostingProvider": "Unknown"
        }
