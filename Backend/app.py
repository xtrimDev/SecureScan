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
import requests as pyrequests
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
                "hostingProvider": whois_data.get("hostingProvider", "Unknown")
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

@App.route('/api/summarize', methods=["POST"])
def summarize_log():
    data = request.get_json()
    log = data.get('log', '')
    scan_type = data.get('type', '')
    if not log or scan_type not in ("xss", "sql"):
        return jsonify({"error": "Invalid input."}), 400
    gemini_api_key = os.getenv('GEMINI_API_KEY')
    if not gemini_api_key:
        return jsonify({"error": "Gemini API key not set in environment."}), 500
    try:
        # Gemini API endpoint for text summarization (using 2.0-flash, matching curl example)
        endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={gemini_api_key}"
        headers = {"Content-Type": "application/json"}
        prompt = f"Summarize the following {scan_type.upper()} scan log in a concise, human-readable way, highlighting key findings, vulnerabilities, and important events.\n\nReturn the summary as well-structured, styled HTML suitable for direct display in a web UI. Use clear sections, headings, and lists where appropriate for easy reading.\n\nLog:\n{log}"
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": prompt}
                    ]
                }
            ]
        }
        response = pyrequests.post(endpoint, json=payload, headers=headers, timeout=60)
        if response.status_code != 200:
            return jsonify({"error": f"Gemini API error: {response.text}"}), 500
        data = response.json()
        summary = data.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', '')
        if not summary:
            summary = "No summary returned by Gemini."
        return jsonify({"summary": summary})
    except Exception as e:
        return jsonify({"error": f"Gemini summarization failed: {str(e)}"}), 500

if __name__ == "__main__":
    App.run(debug=False)