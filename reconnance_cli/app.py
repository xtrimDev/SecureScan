from utils.tools import is_tool_installed, install_tool
from utils.network import get_ip_from_host, get_robots_txt, run_nmap
from utils.cms import detect_cms
from utils.whois_lookup import get_whois_info
from utils.dns_utils import get_records
from utils.ssl_utils import fetch_ssl_certificate
from utils.output import print_header, print_info, print_error, print_json, print_data
from utils.header_analysis import analyze_security_headers, print_security_report

import requests
import re
from urllib.parse import urlparse

def is_valid_url(url):
    regex = re.compile(
        r'^(https?|ftp):\/\/'  
        r'([\w.-]+)'          
        r'(:\d+)?'             
        r'(\/[^\s]*)?$',       
        re.IGNORECASE
    )

    if not re.match(regex, url):
        return False

    parsed = urlparse(url)
    return all([parsed.scheme, parsed.netloc])

def main():
    print("Enter the website Url to reconnance: ", end="");
    url = input();

    if not is_valid_url(url): 
        print_error("Enter a valid url");
        return;

    print_header("Active reconnaissance gathering started...")

    host_match = re.search(r"//([^/]+)", url)
    if not host_match:
        print_error("Invalid URL. Could not extract host.")
        return

    host = host_match.group(1)
    ip = get_ip_from_host(host)
    print_info(f"IP Address: {ip}")

    try:
        data = requests.get(url, timeout=10) 
        cms = detect_cms(data)
        print_info(f"CMS: {cms or 'Not detected'}")

        if data.status_code == 200:
            server = data.headers.get('Server', 'Unknown')

            match = re.search(r"\((.*?)\)", server)
            if match:
                os = match.group(1)  
            else:
                os = "Unknown"

            print_info(f"OS: {os}")
            print_info(f"Server: {server}")

            print_info("Header analysis in progress...")
            analysis = analyze_security_headers(data.headers)
            print_security_report(analysis)
            
        else:
            print_error(f"Failed to access URL, status code: {data.status_code}")
    except requests.RequestException as e:
        print_error(f"Request failed: {e}")

    get_robots_txt(host)

    subdomains_url = f"https://crt.sh/json?q={host}"
    try:
        response = requests.get(subdomains_url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            subdomains = set()
            for entry in data:
                names = entry['name_value'].split('\n')
                for name in names:
                    if host in name:
                        subdomains.add(name.replace('*.', ''))
            print_info("Subdomains found:")
            for s in subdomains:
                print(" - ", end="")
                print_data(f"{s}")
        else:
            print_error(f"crt.sh lookup failed: {response.status_code}")
    except Exception as e:
        print_error(f"Subdomain enumeration failed: {e}")

    if not is_tool_installed("whois"):
        install_tool("whois")

    whois_data = get_whois_info(host)
    print_json(whois_data)

    try:
        cert = fetch_ssl_certificate(host)
        print_info("SSL Certificate:")
        print_json(cert)
    except Exception as e:
        print_error(f"SSL fetch failed for host {host}: {e}")

    run_nmap(host)

    get_records(host)

if __name__ == "__main__":
    main()
