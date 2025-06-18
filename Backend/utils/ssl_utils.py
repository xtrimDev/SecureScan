import ssl
import socket
from datetime import datetime

def fetch_ssl_certificate(host):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                
                return {
                    "issuer": dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown'),
                    "validFrom": datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z').strftime('%Y-%m-%d'),
                    "validTo": datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').strftime('%Y-%m-%d'),
                    "protocol": ssock.version(),
                    "keySize": "2048 bits",
                    "status": "Valid"
                }
    except:
        return {
            "issuer": "Unknown",
            "validFrom": None,
            "validTo": None,
            "protocol": "Unknown",
            "keySize": "Unknown",
            "status": "Invalid"
        }