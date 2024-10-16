import psutil
import socket
import socks
import time
from pprint import pprint
import ipwhois
import requests



# URL to the ad server blacklist
AD_SERVERS_URL = "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt"

# Function to download and parse the blacklist from the provided URL
def download_blacklist(url=AD_SERVERS_URL):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors
        # Parse the response text by splitting each line and capturing only the domain part
        return set([line.split()[1].strip() for line in response.text.splitlines() if line.strip() and not line.startswith('#')])
    except requests.RequestException as e:
        print(f"Error downloading the ad server list: {e}")
        return set()  # Return an empty set if download fails


# TODO: Set up local mitmproxy
"""
mitmdump_process = subprocess.Popen(
    ["mitmdump", "-q", "-s", "./utils/response_interceptor.py", "--listen-port", "8082"],
    stdout=sys.stdout,
    stderr=sys.stderr,
)
"""

def get_hostname(ip_address):
    try:
        domain_name = socket.gethostbyaddr(ip_address)
        print(f"Domain: {domain_name}")
    except socket.herror:
        print("No domain associated with this IP")

# Whois Lookup
def whois_lookup(ipv6):
    try:
        obj = ipwhois.IPWhois(ipv6)
        result = obj.lookup_rdap()
        pprint(result)
        print("")
        network = result.get('network', {}).get('name', None)
        print(network)
        return result
    except Exception as e:
        return None

# Set up the SOCKS5 proxy for routing traffic
def create_socks5_proxy():
    # Set the default proxy to mitmproxy running on localhost:8080
    socks.set_default_proxy(socks.SOCKS5, "localhost", 8080)
    socket.socket = socks.socksocket

# Check if a process is Chrome
def is_chrome(proc_name):
    return "chrome" in proc_name.lower()

# Function to monitor Chrome's network connections
def monitor_chrome_connections(block=True):
    while True:
        for proc in psutil.process_iter(['pid', 'name']):
            if is_chrome(proc.info['name']) and not block:
                    print('CHROME')
                    pprint(proc.info)
                    print('')
                    break

            elif is_chrome(proc.info['name']) and block:
                try:
                    connections = proc.connections(kind='inet')
                    for conn in connections:
                        if conn.status == psutil.CONN_ESTABLISHED:
                            originating_ip = conn.laddr.ip
                            destination_ip = conn.raddr.ip
                            get_hostname(destination_ip)
                            #whois_lookup(destination_ip)
                            #print(f"Intercepting Chrome connection: {conn.laddr} -> {conn.raddr}")
                            #route_traffic_through_proxy(conn.raddr)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    # Ignore processes that we cannot access or that no longer exist
                    pass
        time.sleep(1)  # Check every second

# Function to route traffic through the SOCKS5 proxy
def route_traffic_through_proxy(remote_addr):
    create_socks5_proxy()

    # Assuming remote_addr is a tuple (IP, port) that Chrome is trying to connect to
    if remote_addr:
        ip, port = remote_addr
        print(f"Routing traffic to {ip}:{port} through proxy")

        # Create a socket connection to the remote server via the SOCKS5 proxy
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))

            # Send a basic request (you would replace this with actual traffic from Chrome)
            sock.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            response = sock.recv(4096)
            print("Received response:")
            print(response.decode())
        except Exception as e:
            print(f"Error routing traffic: {e}")
        finally:
            sock.close()

if __name__ == "__main__":
    print("Monitoring Chrome's traffic and routing through SOCKS5 proxy...")
    #monitor_chrome_connections()
    blacklist = download_blacklist()
    print(blacklist)

