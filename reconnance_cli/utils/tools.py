import subprocess

def is_tool_installed(tool_name):
    try:
        subprocess.run([tool_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        return False

def install_tool(tool_name):
    print(f"Installing {tool_name}...")
    try:
        subprocess.run(['sudo', 'apt', 'update'], check=True)
        subprocess.run(['sudo', 'apt', 'install', '-y', tool_name], check=True)
        print(f"{tool_name} installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install {tool_name}: {e}")
