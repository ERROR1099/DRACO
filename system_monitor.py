import psutil
import time
from colorama import init, Fore, Style

init(autoreset=True)

class SystemMonitor:
    def __init__(self):
        pass

    def get_system_info(self):
        """Collect comprehensive system information"""
        print(f"{Fore.CYAN}System Resource Monitor{Style.RESET_ALL}")
        
        # CPU Information
        print(f"\n{Fore.YELLOW}CPU Information:{Style.RESET_ALL}")
        print(f"Physical Cores: {psutil.cpu_count(logical=False)}")
        print(f"Total Cores: {psutil.cpu_count(logical=True)}")
        print(f"CPU Usage: {psutil.cpu_percent()}%")

        # Memory Information
        print(f"\n{Fore.YELLOW}Memory Information:{Style.RESET_ALL}")
        memory = psutil.virtual_memory()
        print(f"Total Memory: {memory.total / (1024 ** 3):.2f} GB")
        print(f"Available Memory: {memory.available / (1024 ** 3):.2f} GB")
        print(f"Memory Usage: {memory.percent}%")

        # Disk Information
        print(f"\n{Fore.YELLOW}Disk Information:{Style.RESET_ALL}")
        disk = psutil.disk_usage('/')
        print(f"Total Disk Space: {disk.total / (1024 ** 3):.2f} GB")
        print(f"Used Disk Space: {disk.used / (1024 ** 3):.2f} GB")
        print(f"Disk Usage: {disk.percent}%")

        # Network Connections
        print(f"\n{Fore.YELLOW}Active Network Connections:{Style.RESET_ALL}")
        for conn in psutil.net_connections():
            print(f"Local Address: {conn.laddr}, Status: {conn.status}")

    def monitor_resources(self, interval=5, duration=60):
        """Monitor system resources over time"""
        print(f"{Fore.CYAN}Continuous Resource Monitoring{Style.RESET_ALL}")
        start_time = time.time()
        
        while time.time() - start_time < duration:
            print(f"\n{Fore.GREEN}Resource Snapshot:{Style.RESET_ALL}")
            print(f"CPU Usage: {psutil.cpu_percent()}%")
            print(f"Memory Usage: {psutil.virtual_memory().percent}%")
            time.sleep(interval)

def main():
    monitor = SystemMonitor()
    
    print("Select Monitoring Mode:")
    print("1. System Information")
    print("2. Continuous Monitoring")
    
    choice = input("Enter your choice (1/2): ")
    
    if choice == '1':
        monitor.get_system_info()
    elif choice == '2':
        monitor.monitor_resources()
    else:
        print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
