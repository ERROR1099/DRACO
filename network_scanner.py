import socket
import ipaddress
import concurrent.futures
from colorama import init, Fore, Style

init(autoreset=True)

class NetworkScanner:
    def __init__(self, target_network):
        self.target_network = target_network

    def scan_port(self, ip, port):
        """Scan a single port on a given IP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                print(f"{Fore.GREEN}[OPEN] {ip}:{port}{Style.RESET_ALL}")
                return port
        except Exception:
            pass
        return None

    def scan_network(self, port_range=(1, 1024)):
        """Scan network for open ports"""
        print(f"{Fore.CYAN}Scanning Network: {self.target_network}{Style.RESET_ALL}")
        
        network = ipaddress.ip_network(self.target_network, strict=False)
        
        for ip in network.hosts():
            ip_str = str(ip)
            print(f"\n{Fore.YELLOW}Scanning IP: {ip_str}{Style.RESET_ALL}")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                futures = [
                    executor.submit(self.scan_port, ip_str, port) 
                    for port in range(port_range[0], port_range[1])
                ]
                
                for future in concurrent.futures.as_completed(futures):
                    future.result()

def main():
    try:
        target = input("Enter network to scan (e.g., 192.168.1.0/24): ")
        scanner = NetworkScanner(target)
        scanner.scan_network()
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
