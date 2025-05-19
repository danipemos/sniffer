import requests
import os
import netifaces
import configparser
import config_search

config = configparser.ConfigParser()
config.read(config_search.search_config())

def get_VPN_config():
    vpn_server = config.get('VPN', 'Server')
    vpn_port = config.get('VPN', 'Port', fallback="51821")
    PASSWORD = config.get('VPN', 'Password', fallback="sniffer")
    BASE_URL = f'http://{vpn_server}:{vpn_port}'
    CLIENT_NAME = os.uname().nodename

    session = requests.Session()

    # Authentication
    r = session.get(f'{BASE_URL}/api/session')
    r.raise_for_status()
    info = r.json()

    if info.get('requiresPassword') and not info.get('authenticated'):
        login = session.post(f'{BASE_URL}/api/session', json={'password': PASSWORD})
        login.raise_for_status()

    # Create client
    create = session.post(f'{BASE_URL}/api/wireguard/client', json={'name': CLIENT_NAME})
    create.raise_for_status()
    print(f"Client '{CLIENT_NAME}' created")

    # Search for the client ID
    list_clients = session.get(f'{BASE_URL}/api/wireguard/client')
    list_clients.raise_for_status()
    clients = list_clients.json()

    client_id = None
    for c in clients:
        if c.get('name') == CLIENT_NAME:
            client_id = c.get('id')
            break

    if not client_id:
        raise Exception("Could not find the ID of the newly created client.")

    print(f"Client ID: {client_id}")

    # Download the configuration
    config_response = session.get(f'{BASE_URL}/api/wireguard/client/{client_id}/configuration')
    config_response.raise_for_status()

    os.makedirs('/home/sniffer', exist_ok=True)
    with open('/home/sniffer/wg0.conf', 'w') as f:
        f.write(config_response.text)

    print(f"Configuration saved to /home/sniffer/wg0.conf")

def add_device():
    host = config.get('WEB', 'Server')
    port = config.getint('WEB', 'Port', fallback=8000)
    url = f'http://{host}:{port}/monitorize/add-device/'
    try:
        ip = netifaces.ifaddresses('wg0')[netifaces.AF_INET][0]['addr']
    except (ValueError, KeyError, IndexError):
        raise Exception("Could not get IP address for interface 'wg0'.")

    data = {
        "hostname": os.uname().nodename,
        "ip": ip,
    }

    response = requests.post(url, data=data)
    response.raise_for_status()
    public_key = response.json().get('public_key')
    if not public_key:
        raise Exception("No public_key found in response.")

    ssh_dir = '/home/sniffer/.ssh'
    os.makedirs(ssh_dir, exist_ok=True)
    authorized_keys_path = os.path.join(ssh_dir, 'authorized_keys')
    with open(authorized_keys_path, 'a') as f:
        f.write(f"{public_key}\n")

    print(f"Public key added to {authorized_keys_path}")


try:
    get_VPN_config()
    os.system('sudo wg-quick up /home/sniffer/wg0.conf')
    add_device()
except Exception as e:
    print(f"An error occurred: {e}")