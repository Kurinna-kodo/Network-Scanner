import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import scapy.all as scapy
import requests
import logging

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
    except (socket.timeout, socket.error) as e:
        logging.warning(f"Port {port} on {ip} is closed or filtered. Error: {e}")
        return f"Port {port} on {ip} is closed or filtered"

def scan_ports_on_device(device):
    ip = device['ip']
    ports = range(1, 1025)  # Example range, can be adjusted
    logging.info(f"Scanning ports on {ip}")
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in ports]
        open_ports = [future.result() for future in as_completed(futures) if "open" in future.result()]
    return open_ports

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
    
if __name__ == "__main__":
    target_range = input("Enter target IP range (e.g., 192.168.0.1/24): ")
    devices = scan_network(target_range)
    for device in devices:
        vendor = get_mac_vendor(device['mac'])
        print(f"Device IP: {device['ip']}, MAC: {device['mac']}, Vendor: {vendor}")
        logging.info(f"Scanning {device['ip']} for open ports...")
        open_ports = scan_ports_on_device(device)
        for port_info in open_ports:
            print(port_info)
