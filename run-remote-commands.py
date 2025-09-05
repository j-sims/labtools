import json
import paramiko

# Load hosts from JSON file
with open('hosts.json') as f:
    hosts = json.load(f)

with open('commands.json', 'r') as f:
        commands = json.load(f)

for host in hosts:
    hostname = host['hostname']
    port = host.get('port', 22)
    username = host['username']
    password = host['password']
    print(f"Connecting to {hostname}...")
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, port=port, username=username, password=password, timeout=10)
        host_status = 'complete'
        for cmd in commands:
            command_str = cmd['command']
            print(f"Running command on {hostname}: {command_str}")
            stdin, stdout, stderr = ssh.exec_command(command_str)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status != 0:
                print(f"Command failed on {hostname}: {command_str}")
                host_status = 'failed'
                break
        ssh.close()
    except Exception as e:
        print(f"Failed to connect or run commands on {hostname}: {e}")
        host_status = 'failed'
    print(f"Host {hostname} marked as {host_status}")
