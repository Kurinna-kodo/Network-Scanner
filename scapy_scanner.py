import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import scapy.all as scapy
import requests
import logging
import time

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    handlers=[logging.FileHandler("network_scanner.log"),
                              logging.StreamHandler()])

def scan_network(ip):
    logging.info(f"Scanning network: {ip}")
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered, unanswered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)
    devices = [{'ip': packet[1].psrc, 'mac': packet[1].hwsrc} for packet in answered]
    logging.info(f"Found {len(devices)} devices.")
    return devices

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((ip, port))
            logging.info(f"Port {port} on {ip} is open.")
            return f"Port {port} on {ip} is open"
    except (socket.timeout, socket.error):
        return None

def scan_ports_on_device(device):
    ip = device['ip']
    ports = range(1, 1025)  # Example range, can be adjusted
    open_ports = []
    open_ports_services = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in ports]
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                if "open" in result:
                    open_ports.append(result)
                else:
                    port = int(result.split()[1])  # Extract port number from result
                    service = discover_service(ip, port)  # Discover service for open port
                    open_ports_services.append((port, service))
    return open_ports_services

def get_mac_vendor(mac_address):
    logging.info(f"Looking up vendor for MAC: {mac_address}")
    base_url = "https://api.macvendors.com/"
    try:
        response = requests.get(base_url + mac_address)
        if response.status_code == 200:
            vendor = response.text  # Manufacturer's name
            logging.info(f"Vendor found for {mac_address}: {vendor}")
            return vendor
        else:
            logging.warning(f"Vendor lookup failed for {mac_address}. Status code: {response.status_code}")
            return "Vendor lookup failed"
    except requests.RequestException as e:
        logging.error(f"Request failed: {e}")
        return f"Request failed: {e}"
    
def discover_service(ip, port):
    service_info = "Unknown service"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((ip, port))
            
            # Send a basic HTTP request if port 80; adjust accordingly for other services
            if port == 80:
                s.sendall(b"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n")
            # Send a basic FTP command if port 21
            elif port == 21:
                s.sendall(b"HELP\r\n")
            # Send a basic SMTP command if port 25
            elif port == 25:
                s.sendall(b"EHLO example.com\r\n")
            # Send a DNS query if port 53
            elif port == 53:
                s.sendall(b"example.com\r\n")
            
            # Wait for a response
            response = s.recv(1024).decode('utf-8', 'ignore')
            
            if "HTTP" in response:
                service_info = "HTTP"
            elif "FTP" in response:
                service_info = "FTP"
            elif "SMTP" in response:
                service_info = "SMTP"
            elif "DNS" in response:
                service_info = "DNS"
            # Add more service checks as needed
            
    except Exception:
        # Suppress warning logs for connection errors or timeouts
        pass  # Do nothing in case of errors or timeouts
        
    return service_info
    
SCAN_DELAY = 2 

if __name__ == "__main__":
    target_range = input("Enter target IP range (e.g., 192.168.0.1/24): ")
    devices = scan_network(target_range)
    print(f"Found {len(devices)} devices:")
    for device in devices:
        vendor = get_mac_vendor(device['mac'])
        print(f"Device IP: {device['ip']}, MAC: {device['mac']}, Vendor: {vendor}")
        print(f"Scanning {device['ip']} for open ports...")
        open_ports_services = scan_ports_on_device(device)
        for port, service in open_ports_services:
            logging.info(f"Port: {port}, Service: {service}")

        


        
