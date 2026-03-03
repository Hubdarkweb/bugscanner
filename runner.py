import sys
import subprocess
import time

def generate_ips_from_cidr(cidr):
    import ipaddress
    ip_list = []
    try:
        network = ipaddress.ip_network(cidr)
        for ip in network.hosts():
            ip_list.append(ip)
    except ValueError as e:
        print(f"Error: {e}")
    return ip_list

def run_scan(args):
    """
    Run the scanner as a subprocess and yield output line by line for SSE streaming.
    args: arguments extracted from the web form, passed as a list of strings
          e.g., ['python3', 'scanner.py', '-m', 'direct', '-f', 'targets.txt']
    """
    try:
        # We need to run scanner.py with python3 and stdbuf/PYTHONUNBUFFERED to force unbuffered output
        # In termux, PYTHONUNBUFFERED=1 usually does the trick
        import os
        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'

        process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
            bufsize=1 # Line buffered
        )

        for line in process.stdout:
            # Yield each line to the Flask generator
            yield line
            
        process.stdout.close()
        process.wait()
    except Exception as e:
        yield f"Error running scanner: {str(e)}\n"
