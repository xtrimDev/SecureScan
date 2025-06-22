import socket
import requests
import subprocess

def get_ip_from_host(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return "Unknown"

def get_robots_txt(host):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(f"https://{host}/robots.txt", headers=headers, timeout=5)
        if response.status_code == 200:
            return response.text
        return ""
    except requests.exceptions.RequestException:
        return ""

def run_nmap(host):
    try:
        result = subprocess.run(['nmap', '-Pn', '-T4', host], capture_output=True, text=True, timeout=40)

        ports = []
        for line in result.stdout.split('\n'):
            if '/tcp' in line and 'open' in line.lower():
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
    except subprocess.SubprocessError:
        return []
    except Exception:
        return []
