import subprocess
import re
from .output import print_info, print_error

def get_whois_info(host):
    print_info("Running Whois...")

    try:
        result = subprocess.run(['whois', host], capture_output=True, text=True, timeout=10)
        output = result.stdout

        def safe_search(pattern):
            match = re.search(pattern, output)
            return match.group(1).strip() if match else None

        return {
            "domain_info": {
                "domain_name": safe_search(r"Domain Name:\s*(.+)"),
                "registry_domain_id": safe_search(r"Registry Domain ID:\s*(.+)")
            },
            "registrar": {
                "name": safe_search(r"Registrar:\s*(.+)"),
                "url": safe_search(r"Registrar URL:\s*(.+)"),
                "whois_server": safe_search(r"Registrar WHOIS Server:\s*(.+)"),
                "abuse_email": safe_search(r"Registrar Abuse Contact Email:\s*(.+)"),
                "abuse_phone": safe_search(r"Registrar Abuse Contact Phone:\s*(.+)"),
                "iana_id": safe_search(r"Registrar IANA ID:\s*(.+)")
            },
            "dates": {
                "creation_date": safe_search(r"Creation Date:\s*(.+)"),
                "updated_date": safe_search(r"Updated Date:\s*(.+)"),
                "expiry_date": safe_search(r"Registry Expiry Date:\s*(.+)")
            },
            "name_servers": re.findall(r"Name Server:\s*(.+)", output),
            "dnssec": safe_search(r"DNSSEC:\s*(.+)"),
            "domain_status": safe_search(r"Domain Status:\s*(.+)")
        }
    except Exception as e:
        return {"error": str(e)}
