from rich import print as rprint
import json

def print_info(msg):
    rprint(f"[cyan][INFO][/cyan] {msg}")

def print_error(msg):
    rprint(f"[bold red][ERROR][/bold red] {msg}")

def print_header(msg):
    rprint(f"\n[bold green]{msg}[/bold green]\n")

def print_json(data):
    rprint(json.dumps(data, indent=2))

def print_data(data):
    rprint(f"[green]{data}[/green]")
