import ssl
import socket
from datetime import datetime

def fetch_ssl_certificate(host):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                
                issuer = dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown')
                valid_from = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                valid_to = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                protocol = ssock.version()
                
                # Check if the certificate is currently valid
                now = datetime.utcnow()
                status = "Valid" if valid_from <= now <= valid_to else "Expired"
                
                return {
                    "issuer": issuer,
                    "validFrom": valid_from.strftime('%Y-%m-%d'),
                    "validTo": valid_to.strftime('%Y-%m-%d'),
                    "protocol": protocol,
                    "keySize": "Unknown", 
                    "status": status
                }
    except Exception as e:
        print(f"Error fetching certificate: {e}")
        return {
            "issuer": "Unknown",
            "validFrom": None,
            "validTo": None,
            "protocol": "Unknown",
            "keySize": "Unknown",
            "status": "Invalid"
        }
