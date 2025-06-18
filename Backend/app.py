from flask import Flask, request, jsonify
from utils.tools import is_tool_installed, install_tool
from utils.network import get_ip_from_host, get_robots_txt, run_nmap
from utils.cms import detect_cms
from utils.whois_lookup import get_whois_info
from utils.dns_utils import get_records
from utils.ssl_utils import fetch_ssl_certificate
from utils.header_analysis import analyze_security_headers
import requests
import re

import subprocess 


from flask_cors import CORS, cross_origin
app = Flask(__name__)

CORS(app)

app = Flask(__name__)

def gather_reconnaissance(url):
    host_match = re.search(r"//([^/]+)", url)
    if not host_match:
        return {"error": "Invalid URL. Could not extract host."}

    host = host_match.group(1)
    ip = get_ip_from_host(host)
    
    try:
        data = requests.get(url, timeout=10)
        cms = detect_cms(data)
        server = data.headers.get('Server', 'Unknown')
        
        match = re.search(r"\((.*?)\)", server)
        os = match.group(1) if match else "Unknown"
        
        # Get security headers
        security_headers = analyze_security_headers(data.headers)
        
        # Get robots.txt
        robots_content = get_robots_txt(host)
        
        # Get subdomains
        subdomains = set()
        subdomains_url = f"https://crt.sh/json?q={host}"
        response = requests.get(subdomains_url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                names = entry['name_value'].split('\n')
                for name in names:
                    if host in name:
                        subdomains.add(name.replace('*.', ''))
        
        # Get WHOIS data
        whois_data = get_whois_info(host)
        
        # Get SSL certificate
        ssl_data = fetch_ssl_certificate(host)
        
        # Get open ports
        ports_data = run_nmap(host)
        
        # Get DNS records
        dns_records = get_records(host)
        
        reconnaissance = {
            "serverInfo": {
                "ip": ip,
                "OS": os,
                "webServerType": server,
                "cms": cms or "Not detected"
            },
            "openPorts": ports_data,
            "dnsRecords": dns_records,
            "subdomains": list(subdomains),
            "securityHeaders": security_headers,
            "robotsTxt": robots_content,
            "whois": whois_data,
            "ssl": ssl_data
        }
        
        return reconnaissance
        
    except requests.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}
    except Exception as e:
        return {"error": f"An error occurred: {str(e)}"}

@app.route('/reconnaissance/<path:url>')
@cross_origin()
def get_reconnaissance(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    result = gather_reconnaissance(url)
    return jsonify(result)
# python3 xsstrike.py -u "https://xtrimnotes.in" --crawl -l 3

    # cmd = ['python3', 'XsStrike/xsstrike.py', '-u', url, '--crawl', '-l', '5']
    # result = subprocess.run(cmd, capture_output=True, text=True)
    # return result.stdout
def gather_vulnerability(url, server, open_ports, missing_headers):
    vulnerabilities = []

    outdated_versions = {
        "Apache": {
            "2.4.29": {
                "description": "This version of Apache is vulnerable to multiple known CVEs including CVE-2017-15710.",
                "risk": "high"
            },
            "2.4.38": {
                "description": "This version of Apache has known DoS vulnerabilities.",
                "risk": "medium"
            }
        },
        "nginx": {
            "1.14.0": {
                "description": "nginx 1.14.0 is known to have HTTP/2 vulnerabilities (e.g., CVE-2019-9511).",
                "risk": "high"
            }
        }
    }

    if server:
        name_parts = server.split()
        vendor = name_parts[0]
        version = name_parts[1] if len(name_parts) > 1 else ""
        version_info = outdated_versions.get(vendor, {}).get(version)

        if version_info:
            vulnerabilities.append({
                "name": f"Outdated {vendor} Server",
                "description": version_info["description"],
                "risk": version_info["risk"],
                "affectedComponent": f"{vendor} {version}"
            })

    if open_ports:
        open_ports_str = ", ".join(map(str, open_ports))
        vulnerabilities.append({
            "name": "Sensitive Ports Open",
            "description": f"Ports {open_ports_str} are open and may expose services to unauthorized access.",
            "risk": "high",
        })

    if missing_headers:
        headers_str = ", ".join(missing_headers)
        vulnerabilities.append({
            "name": "Missing Security Headers",
            "description": f"The following important HTTP headers are missing: {headers_str}.",
            "risk": "medium",
        })

    return {"vulnerabilities": vulnerabilities}

@app.route('/vulnerability', methods=['POST'])
@cross_origin()
def get_vulnerability():
    data = request.get_json()

    url = data.get('url', '')
    server = data.get('server', '')
    open_ports = data.get('open_ports', [])
    missing_headers = data.get('missing_headers', [])

    print(open_ports, missing_headers)

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    output = gather_vulnerability(url, server, open_ports, missing_headers)
    return jsonify(output)

if __name__ == "__main__":
    app.run(debug=True)
