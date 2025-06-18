import subprocess
import requests
import re
from .output import print_info, print_error, print_data, print_json
from rich.console import Console
from rich.table import Table

console = Console()

def get_ip_from_host(host):
    try:
        result = subprocess.run(['ping', '-c', '1', host], capture_output=True, text=True, timeout=5)
        match = re.search(r"\((.*?)\)", result.stdout)
        return match.group(1) if match else "Unknown"
    except subprocess.TimeoutExpired:
        print_error("Ping timed out.")
        return "Unknown"

def get_robots_txt(host):
    print_info(f"Checking for robots.txt at http://{host}/robots.txt")
    try:
        res = requests.get(f"http://{host}/robots.txt", timeout=5)
        if res.status_code == 200:
            print_info("robots.txt found:")
            print_data(res.text)
        else:
            print_info("robots.txt not found.")
    except Exception as e:
        print_error(f"Failed to get robots.txt: {e}")

def run_nmap(host):
    print_info("Running Nmap...")
    try:
        result = subprocess.run(['nmap', '-Pn', host], capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            pattern = r"(\d+/tcp)\s+open\s+(\w+)"
            matches = re.findall(pattern, result.stdout)

            if matches:
                # Create a rich table
                table = Table(title=f"Open Ports for {host}")
                table.add_column("Port", style="cyan", no_wrap=True)
                table.add_column("Status", style="green")
                table.add_column("Service", style="magenta")

                for port, service in matches:
                    table.add_row(port, "open", service)

                console.print(table)
            else:
                console.print("[yellow]No open ports found.[/yellow]")
        else:
            print_error("Nmap error.")
    except subprocess.TimeoutExpired:
        print_error("Nmap scan timed out.")