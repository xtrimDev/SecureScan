import dns.resolver
import dns.zone
import dns.query
from .output import print_info, print_data, print_error, print_header, print_json

def get_records(domain):
    print_header(f"DNS Records for {domain}")
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            print_info(f"{rtype} Records:")
            for r in answers:
                print_data(f" - {r.to_text()}")
        except Exception:
            print_error(f"No {rtype} records found.")
