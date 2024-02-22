import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import scapy.all as scapy
import requests
import logging
import pandas as pd

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    handlers=[logging.FileHandler("network_scanner.log"),
                              logging.StreamHandler()])

def scan_network(ip):
    """
    Scans the network for devices using ARP requests.
    """
    logging.info(f"Scanning network: {ip}")
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered, _ = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)
    devices = [{'ip': packet[1].psrc, 'mac': packet[1].hwsrc} for packet in answered]
    logging.info(f"Found {len(devices)} devices.")
    return devices

def scan_port(ip, port):
    """
    Tries to connect to a specified port and returns the port if open.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((ip, port))
            logging.info(f"Port {port} on {ip} is open.")
            return port  # Return just the port number if open
    except (socket.timeout, socket.error):
        return None

def scan_ports_on_device(device):
    """
    Scans for open ports on a device within a specified range.
    """
    ip = device['ip']
    ports = range(1, 1025)  # Example range, can be adjusted
    open_ports = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in ports]
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)
    return open_ports

def get_mac_vendor(mac_address):
    """
    Looks up the vendor for a given MAC address.
    """
    logging.info(f"Looking up vendor for MAC: {mac_address}")
    base_url = "https://api.macvendors.com/"
    try:
        response = requests.get(base_url + mac_address)
        if response.status_code == 200:
            vendor = response.text
            logging.info(f"Vendor found for {mac_address}: {vendor}")
            return vendor
        else:
            logging.warning(f"Vendor lookup failed for {mac_address}. Status code: {response.status_code}")
            return "Vendor lookup failed"
    except requests.RequestException as e:
        logging.error(f"Request failed: {e}")
        return "Request failed"

def discover_service(ip, port):
    """
    Attempts to identify the service running on an open port.
    """
    # Implementation unchanged; adjust as per your actual service discovery needs.
    service_info = "Unknown service"
    # This simplified logic is placeholder. Detailed implementation based on the original script.
    return service_info

if __name__ == "__main__":
    target_range = input("Enter target IP range (e.g., 192.168.0.1/24): ")
    devices = scan_network(target_range)
    logging.info(f"Found {len(devices)} devices")
    
    results = []
    for device in devices:
        vendor = get_mac_vendor(device['mac'])
        open_ports = scan_ports_on_device(device)
        for port in open_ports:
            service = discover_service(device['ip'], port)  # Placeholder for actual service discovery
            results.append({
                'IP': device['ip'],
                'MAC': device['mac'],
                'Vendor': vendor,
                'Port': port,
                'Service': service  # Assuming service discovery provides meaningful output
            })

    df = pd.DataFrame(results)
    df.to_excel('scan_results.xlsx', index=False)
    print(df)

        


        
