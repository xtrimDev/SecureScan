import socket
import requests
import subprocess
import json
from .output import print_info, print_error, print_data, print_json
from rich.console import Console
from rich.table import Table

console = Console()

def get_ip_from_host(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return "Unknown"

def get_robots_txt(host):
    try:
        response = requests.get(f"https://{host}/robots.txt", timeout=10)
        if response.status_code == 200:
            return response.text
        return ""
    except:
        return ""

def run_nmap(host):
    try:
        # Run nmap with common ports
        result = subprocess.run(['nmap', '-Pn', host], capture_output=True, text=True, timeout=40)
        
        ports = []
        for line in result.stdout.split('\n'):
            if 'open' in line.lower():
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0].split('/')[0]
                    service = parts[2]
                    ports.append({
                        "port": int(port),
                        "service": service,
                        "status": "Open",
                    })
        return ports
    except:
        return []