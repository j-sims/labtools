import json
import paramiko
import argparse
import os
import re

# Argument parser for verbose, quiet, and host filtering
parser = argparse.ArgumentParser(description='Run remote commands with optional verbose output and host filtering.')
parser.add_argument('-v', '--verbose', action='store_true', help='Print command outputs')
parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode: hide host status output')
parser.add_argument('-c', '--commands-file', type=str, default='commands.json', help='Commands file to use (default: commands.json)')
parser.add_argument('-l', '--host-filter', type=str, default=None, help='Comma-separated list of regex patterns to filter hosts by hostname')
args = parser.parse_args()
verbose = args.verbose
quiet = args.quiet
commands_file = args.commands_file
host_filter_raw = args.host_filter

# Compile host filter patterns if provided
host_patterns = []
if host_filter_raw:
    # Split on comma, trim whitespace, discard empties
    pieces = [p.strip() for p in host_filter_raw.split(',')]
    pieces = [p for p in pieces if p]
    if not pieces:
        print("Host filter provided but no valid patterns found; continuing without filter.")
    else:
        try:
            host_patterns = [re.compile(p) for p in pieces]
        except re.error as e:
            print(f"Invalid regular expression in host filter: {e}")
            exit(1)

def host_matches_any(hostname, patterns):
    if not patterns:
        return True
    for pat in patterns:
        if pat.search(hostname):
            return True
    return False

if not os.path.isfile(commands_file):
    print(f"Commands file '{commands_file}' not found.")
    exit(1)

# Load hosts and commands
with open('hosts.json') as f:
    hosts = json.load(f)
with open(commands_file) as f:
    commands = json.load(f)

# Apply host filtering (only those whose hostname matches any provided pattern)
filtered_hosts = [h for h in hosts if host_matches_any(h.get('hostname',''), host_patterns)]

if host_patterns and not filtered_hosts:
    print("No hosts matched the provided host filter patterns. Exiting.")
    exit(0)

if host_patterns and not quiet:
    matched_count = len(filtered_hosts)
    total_count = len(hosts)
    print(f"Host filter applied: {matched_count}/{total_count} hosts will be processed.")

# Iterate over filtered hosts (or all if no filter)
for host in filtered_hosts if host_patterns else hosts:
    hostname = host['hostname']
    port = host.get('port', 22)
    username = host['username']
    password = host['password']
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, port=port, username=username, password=password, timeout=10)
        host_status = 'complete'
        for cmd in commands:
            command_str = cmd['command']
            # Per-command verbosity override
            verbose_command = cmd.get('verbose', None)
            effective_verbose = verbose if verbose_command is None else bool(verbose_command)
            if effective_verbose:
                if not quiet:
                    print(f"Running command on {hostname}: {command_str}")  
            stdin, stdout, stderr = ssh.exec_command(command_str)
            # Capture output
            output = stdout.read()
            if effective_verbose:
                print(f"Output from {hostname}: {output.decode().strip()}")
            exit_status = stdout.channel.recv_exit_status()
            if exit_status != 0:
                print(f"Command failed on {hostname}: {command_str}")
                host_status = 'failed'
                break
        ssh.close()
    except Exception as e:
        print(f"Failed to connect or run commands on {hostname}: {e}")
        host_status = 'failed'
    # Define Unicode symbols and colors
    check_mark = "\u2713"  # ✓
    cross_mark = "\u2717"  # ✗
    green_color = "\033[92m"
    red_color = "\033[91m"
    reset_color = "\033[0m"

    if host_status == 'complete':
        status_icon = f"{green_color}{check_mark}{reset_color}"
    else:
        status_icon = f"{red_color}{cross_mark}{reset_color}"
    if not quiet:
        print(f"Host {hostname} : {host_status} {status_icon}")
    # If quiet is enabled, skip the final host-status line but keep other outputs intact
