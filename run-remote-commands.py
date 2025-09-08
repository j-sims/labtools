import json
import paramiko
import argparse
import os

# Argument parser for verbose flag
parser = argparse.ArgumentParser(description='Run remote commands with optional verbose output.')
parser.add_argument('-v', '--verbose', action='store_true', help='Print command outputs')
parser.add_argument('-c', '--commands-file', type=str, default='commands.json', help='Commands file to use (default: commands.json)')
args = parser.parse_args()
verbose = args.verbose
commands_file = args.commands_file

if not os.path.isfile(commands_file):
    print(f"Commands file '{commands_file}' not found.")
    exit(1)

# Load hosts and commands
with open('hosts.json') as f:
    hosts = json.load(f)
with open(commands_file) as f:
    commands = json.load(f)

for host in hosts:
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
                print(f"Running command on {hostname}: {command_str}")
            stdin, stdout, stderr = ssh.exec_command(command_str)
            # Capture output
            output = stdout.read()
            if effective_verbose:
                print(f"Output from {hostname}:\n{output.decode().strip()}")
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
    print(f"Host {hostname} : {host_status} {status_icon}")
