import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import scapy.all as scapy

def scan_network(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered, unanswered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)
    devices = [{'ip': packet[1].psrc, 'mac': packet[1].hwsrc} for packet in answered]
    return devices

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((ip, port))
            return f"Port {port} on {ip} is open"
    except (socket.timeout, socket.error):
        return f"Port {port} on {ip} is closed or filtered"

def scan_ports_on_device(device):
    ip = device['ip']
    ports = range(1, 1025)  # Example range, can be adjusted
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in ports]
        open_ports = [future.result() for future in as_completed(futures) if "open" in future.result()]
    return open_ports

if __name__ == "__main__":
    target_range = input("Enter target IP range (e.g., 192.168.0.1/24): ")
    devices = scan_network(target_range)
    print(f"Found {len(devices)} devices:")
    for device in devices:
        print(f"Device IP: {device['ip']}, MAC: {device['mac']}")
        print(f"Scanning {device['ip']} for open ports...")
        open_ports = scan_ports_on_device(device)
        for port_info in open_ports:
            print(port_info)
