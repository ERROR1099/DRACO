import requests
import socket
import ipaddress
from colorama import init, Fore, Style

init(autoreset=True)

class IPIntelligence:
    def __init__(self, ip_address):
        self.ip = ip_address

    def validate_ip(self):
        """Validate IP address format"""
        try:
            ipaddress.ip_address(self.ip)
            return True
        except ValueError:
            return False

    def get_ip_geolocation(self):
        """Retrieve IP geolocation information"""
        if not self.validate_ip():
            print(f"{Fore.RED}Invalid IP Address{Style.RESET_ALL}")
            return None

        try:
            response = requests.get(f"https://ipapi.co/{self.ip}/json/")
            data = response.json()
            
            print(f"{Fore.CYAN}IP Geolocation Information{Style.RESET_ALL}")
            print(f"IP: {data.get('ip', 'N/A')}")
            print(f"City: {data.get('city', 'N/A')}")
            print(f"Region: {data.get('region', 'N/A')}")
            print(f"Country: {data.get('country_name', 'N/A')}")
            print(f"Latitude: {data.get('latitude', 'N/A')}")
            print(f"Longitude: {data.get('longitude', 'N/A')}")
            print(f"ISP: {data.get('org', 'N/A')}")
        
        except requests.RequestException as e:
            print(f"{Fore.RED}Error retrieving IP information: {e}{Style.RESET_ALL}")

    def dns_lookup(self):
        """Perform DNS lookup and reverse DNS"""
        try:
            # Forward DNS
            print(f"\n{Fore.YELLOW}DNS Lookup Results{Style.RESET_ALL}")
            print(f"Hostname: {socket.gethostbyaddr(self.ip)[0]}")
            
            # Reverse DNS
            print(f"IP Address: {socket.gethostbyname(socket.gethostbyaddr(self.ip)[0])}")
        
        except (socket.herror, socket.gaierror):
            print(f"{Fore.RED}Unable to perform DNS lookup{Style.RESET_ALL}")

def main():
    try:
        ip = input("Enter IP Address to investigate: ")
        ip_intel = IPIntelligence(ip)
        
        print("\nSelect IP Intelligence Options:")
        print("1. Geolocation Information")
        print("2. DNS Lookup")
        print("3. Both")
        
        choice = input("Enter your choice (1/2/3): ")
        
        if choice == '1':
            ip_intel.get_ip_geolocation()
        elif choice == '2':
            ip_intel.dns_lookup()
        elif choice == '3':
            ip_intel.get_ip_geolocation()
            ip_intel.dns_lookup()
        else:
            print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")
    
    except Exception as e:
        print(f"{Fore.RED}An error occurred: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
