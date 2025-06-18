import dns.resolver
import socket
from .output import print_info, print_data, print_error, print_header, print_json

def get_records(host):
    records = []
    
    # A Records
    try:
        a_records = dns.resolver.resolve(host, 'A')
        for record in a_records:
            records.append({
                "type": "A",
                "data": str(record)
            })
    except:
        pass

    # AAAA Records
    try:
        aaaa_records = dns.resolver.resolve(host, 'AAAA')
        for record in aaaa_records:
            records.append({
                "type": "AAAA",
                "data": str(record)
            })
    except:
        pass

    # MX Records
    try:
        mx_records = dns.resolver.resolve(host, 'MX')
        for record in mx_records:
            records.append({
                "type": "MX",
                "data": f"{record.preference} {str(record.exchange)}"
            })
    except:
        pass

    # TXT Records
    try:
        txt_records = dns.resolver.resolve(host, 'TXT')
        for record in txt_records:
            records.append({
                "type": "TXT",
                "data": str(record)
            })
    except:
        pass

    # NS Records
    try:
        ns_records = dns.resolver.resolve(host, 'NS')
        for record in ns_records:
            records.append({
                "type": "NS",
                "data": str(record)
            })
    except:
        pass

    # CNAME Records
    try:
        cname_records = dns.resolver.resolve(host, 'CNAME')
        for record in cname_records:
            records.append({
                "type": "CNAME",
                "data": str(record)
            })
    except:
        pass

    return records
