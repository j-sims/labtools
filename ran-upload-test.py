#!/bin/env python3
import requests
import json
import sys
import urllib3
import argparse
import paramiko
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # Supresses the self signed cert warning

### Uses ssh to mkdir /ifs/data/test
### Uses RAN to create namespace 'test' with path '/ifs/data/test'
### Uses RAN to PUT filename (specified with -f) on cluster
### Assumes root user for testing, no permissions issues

#### Global: new filename variable to store -f/--file value
filename = None

#### Variables
namespace = 'data'
namespace_path = '/ifs/data/test'
username = 'root'


# Optional host override via CLI
parser = argparse.ArgumentParser(description='Rantesting host override utility')
parser.add_argument('-f', '--file', dest='filename', type=str, default=None, help='Path or identifier to use (stored in filename)')
parser.add_argument('--host', type=str, default=None, help='Override the hardcoded host (e.g., 192.0.2.1)')
parser.add_argument('-p', '--password', type=str, default='a', help='Override the default password "a"')
args, _ = parser.parse_known_args()

# Effective host selection: use CLI override if provided, otherwise fall back to hardcoded default below
host_override = args.host
password_override = args.password

host = host_override if host_override else '172.16.10.10'
PASS = password_override if password_override else 'a'

# Wire parsed value to global filename variable for future reuse
filename = args.filename

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # Supresses the self signed cert warning

CLUSTERIP = host
PORT=8080
USER='root'

uri = "https://%s:%s" % (CLUSTERIP, PORT)
papi = uri + '/platform'
headers = {'Content-Type': 'application/json'}
data = json.dumps({'username': USER, 'password': PASS, 'services': ['platform']})


# uri of the cluster used in the referer header
uri = f"https://{CLUSTERIP}:{PORT}"
# url of Papi used for all further calls to Papi
papi = uri + '/platform'
# Set header as content will provided in json format
headers = {'Content-Type': 'application/json'}
# Create json dictionary for auth
data = json.dumps({'username': USER, 'password': PASS, 'services': ['platform', 'namespace']})
# create a session object to hold cookies
session = requests.Session()
# Establish session using auth credentials
response = session.post(uri + "/session/1/session", data=data, headers=headers, verify=False)
if 200 <= response.status_code < 299:
    # Set headers for CSRF protection. Without these two headers all further calls with be "auth denied"
    session.headers['referer'] = uri
    session.headers['X-CSRF-Token'] = session.cookies.get('isicsrf')
    print("Authorization Successful")
else:
    print("Authorization Failed")
    print(response.content)


def mkdir(hostname, port, user, passwd, path):
    """
    Use Paramiko to SSH into the host and run mkdir -p <path>.
    Returns (success: bool, output: str).
    """
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, port=port, username=user, password=passwd, timeout=10)
        cmd = f'mkdir -p "{path}"'
        stdin, stdout, stderr = ssh.exec_command(cmd)
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        exit_status = stdout.channel.recv_exit_status()
        ssh.close()
        if exit_status == 0:
            return True, out or "(mkdir) success"
        else:
            return False, err or "(mkdir) failed"
    except Exception as e:
        return False, str(e)

def checkdir(hostname, port, user, passwd, path):
    """
    SSH into the host and check if the directory exists.
    Returns True if the directory exists, False otherwise.
    """
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, port=port, username=user, password=passwd, timeout=10)
        # Use a simple test command to check directory existence
        # -d checks if path exists and is a directory
        # Quoting path to be safe with spaces
        cmd = f'test -d "{path}"'
        stdin, stdout, stderr = ssh.exec_command(cmd)
        # We only care about exit status: 0 means exists
        exit_status = stdout.channel.recv_exit_status()
        ssh.close()
        return exit_status == 0
    except Exception:
        # On any SSH/command error, treat as not existing (caller can log if needed)
        return False


def setup(session,host, PORT, USER, PASS, namespace_path):
    if mkdir(host, PORT, username, password, namespace_path):
        #### Create Namespace
        encoded_data = json.dumps({ "path" : namespace_path })
        response = session.put(f"https://{host}:8080/namespace/test",  data=encoded_data, headers=headers, verify=False)
        print(response.status_code)
        print(response.text)

def file_xfer(session, filename):
    session.headers['x-isi-ifs-target-type'] = 'object'
    with open(filename, 'r') as f:
        response = session.put(f"https://{host}:8080/namespace/test/{filename}", data=f, verify=False)
    print(response.status_code)
    print(response.text)

# Entry point: allow running the script directly while preserving existing import-time behavior.
if __name__ == '__main__':
    if not checkdir(host, 22, USER, PASS, namespace_path):
        setup(session, host, 22, USER, PASS, namespace_path)
    if filename:
        file_xfer(session, filename)

