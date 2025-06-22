from flask import Flask, request, jsonify
from flask_cors import CORS, cross_origin

from utils.tools import is_tool_installed, install_tool
from utils.network import get_ip_from_host, get_robots_txt, run_nmap
from utils.cms import detect_cms
from utils.whois_lookup import get_whois_info
from utils.dns_utils import get_records
from utils.ssl_utils import fetch_ssl_certificate
from utils.header_analysis import analyze_security_headers
from utils.valid_url import is_valid_url

import requests
import re
import subprocess

from dotenv import load_dotenv
import os
load_dotenv()

App = Flask(__name__)
CORS(App, resources={r"/api/*": {"origins": os.getenv('FRONTEND_URL')}})

def gather_reconnaissance(url):
    host_match = re.search(r"//([^/]+)", url)

    if not host_match:
        return {"error": "Invalid URL. Could not extract host."}, 400

    host = host_match.group(1)
    ip = get_ip_from_host(host)
    
    try:
        data = requests.get(url, timeout=5)

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

        response = requests.get(subdomains_url, timeout=19)
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
                "cms": cms or "Not detected",
            },
            "openPorts": ports_data,
            "dnsRecords": dns_records,
            "subdomains": list(subdomains),
            "securityHeaders": security_headers,
            "robotsTxt": robots_content,
            "whois": whois_data,
            "ssl": ssl_data
        }
        
        return reconnaissance, 200
        
    except requests.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}, 400
    except Exception as e:
        return {"error": f"An error occurred: {str(e)}"}, 400

@App.route('/api/recon', methods=["POST"])
def get_reconnaissance():
    data = request.get_json()
    url = data.get('url')

    if not url or not is_valid_url(url):
        return jsonify({"error": "Invalid URL provided."}), 400
    
    result, status_code = gather_reconnaissance(url)
    return jsonify(result), status_code

if __name__ == "__main__":
    App.run(debug=False)