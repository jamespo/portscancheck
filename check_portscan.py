#!/usr/bin/env python3
import sys
import argparse
import subprocess
import pathlib

# Nagios Exit Codes
OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3

def parse_nmap_output(stdout):
    """Parses nmap output to find lines with 'open' ports."""
    open_ports = []
    for line in stdout.splitlines():
        # Look for lines that look like a port entry: "80/tcp  open  http"
        # The shell script just used grep -w open
        if 'open' in line.split():
            open_ports.append(line.strip())
    return sorted(open_ports)

def run_nmap(hostname, ip_family=None):
    """Runs nmap and returns the list of open ports."""
    # Using -sT (TCP connect scan) as it doesn't require root, -Pn to skip host discovery
    # Modern nmap uses -Pn instead of -P0.
    cmd = ['nmap', '-sT', '-Pn']
    if ip_family:
        cmd.append(ip_family)
    cmd.append(hostname)
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return parse_nmap_output(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"UNKNOWN: nmap failed with exit code {e.returncode}. Error: {e.stderr}")
        sys.exit(UNKNOWN)
    except FileNotFoundError:
        print("UNKNOWN: nmap command not found. Please install nmap.")
        sys.exit(UNKNOWN)

def main():
    parser = argparse.ArgumentParser(description='Nagios plugin to check for changes in open ports using nmap.')
    parser.add_argument('hostname', help='Server hostname or IP to scan')
    parser.add_argument('directory', nargs='?', default='/etc/nagios/portscancheck',
                        help='Directory to store baseline and results (default: /etc/nagios/portscancheck)')
    parser.add_argument('-6', dest='ipv6', action='store_const', const='-6', help='Use IPv6')
    
    args = parser.parse_args()
    
    hostname = args.hostname
    base_dir = pathlib.Path(args.directory)
    
    # Ensure directory exists
    try:
        base_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"UNKNOWN: Could not create directory {base_dir}: {e}")
        sys.exit(UNKNOWN)
        
    baseline_file = base_dir / f"{hostname}{args.ipv6 or ''}.base"
    
    current_ports = run_nmap(hostname, args.ipv6)
    current_content = "\n".join(current_ports)
    
    if not baseline_file.exists():
        # Initial scan
        try:
            baseline_file.write_text(current_content)
            print(f"OK: Initial scan for {hostname} completed. Baseline created.")
            sys.exit(OK)
        except Exception as e:
            print(f"UNKNOWN: Could not write baseline file: {e}")
            sys.exit(UNKNOWN)
            
    # Compare with baseline
    try:
        baseline_content = baseline_file.read_text().splitlines()
    except Exception as e:
        print(f"UNKNOWN: Could not read baseline file: {e}")
        sys.exit(UNKNOWN)
        
    # Remove empty lines if any
    baseline_content = [line for line in baseline_content if line.strip()]
    
    if current_ports == baseline_content:
        print(f"OK: No changes in open ports for {hostname}.")
        sys.exit(OK)
    else:
        # Ports have changed. Identify what changed.
        added = [p for p in current_ports if p not in baseline_content]
        removed = [p for p in baseline_content if p not in current_ports]
        
        msg_parts = []
        if added:
            # Format nicely, showing only the port part if possible or the whole line
            msg_parts.append(f"OPENED: {', '.join(added)}")
        if removed:
            msg_parts.append(f"CLOSED: {', '.join(removed)}")
            
        print(f"WARNING: Port changes detected for {hostname}. {'; '.join(msg_parts)}")
        sys.exit(WARNING)

if __name__ == '__main__':
    main()
