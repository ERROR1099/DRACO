import os
import sys
import time
import threading
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress
from art import text2art
import pyfiglet
import colorama

# Import custom modules
from network_scanner import NetworkScanner
from system_monitor import SystemMonitor
from ip_info import IPIntelligence
from advanced_tools import AdvancedSecurityTools
from extended_security_tools import ExtendedSecurityTools
from specialized_security_tools import SpecializedSecurityTools
from comprehensive_security_toolkit import ComprehensiveSecurityToolkit

class SecurityToolkitUI:
    def __init__(self):
        colorama.init(autoreset=True)
        self.console = Console()
        self.monitor = SystemMonitor()
        self.advanced_tools = AdvancedSecurityTools()
        self.extended_tools = ExtendedSecurityTools()
        self.specialized_tools = SpecializedSecurityTools()
        self.comprehensive_toolkit = ComprehensiveSecurityToolkit()

    def clear_screen(self):
        """Clear console screen"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def animated_loading(self, message="Processing", duration=2):
        """Create an animated loading effect"""
        with Progress() as progress:
            task = progress.add_task(f"[green]{message}...", total=100)
            while not progress.finished:
                progress.update(task, advance=0.5)
                time.sleep(duration / 100)

    def display_banner(self):
        """Display stylish banner"""
        self.clear_screen()
        banner = text2art("Security Toolkit", font="block")
        self.console.print(Panel(
            Text(banner, style="bold cyan"),
            border_style="bold magenta",
            title="[bold green]Defensive Security Suite[/bold green]"
        ))

    def main_menu(self):
        """Display main menu with rich formatting"""
        while True:
            self.display_banner()
            menu_options = [
                "1. Network Port Scanner",
                "2. System Resource Monitor", 
                "3. IP Intelligence",
                "4. Comprehensive Security Scan",
                "5. Advanced Security Tools",
                "6. Exit"
            ]
            
            self.console.print(Panel(
                "\n".join(menu_options),
                title="[bold blue]Main Menu[/bold blue]",
                border_style="bold green"
            ))

            choice = input("\nEnter your choice (1-6): ")

            if choice == '1':
                self.network_scan_menu()
            elif choice == '2':
                self.system_monitor_menu()
            elif choice == '3':
                self.ip_intelligence_menu()
            elif choice == '4':
                self.comprehensive_scan()
            elif choice == '5':
                self.advanced_tools_menu()
            elif choice == '6':
                self.exit_toolkit()
            else:
                self.console.print("[bold red]Invalid choice. Try again.[/bold red]")
                time.sleep(1)

    def advanced_tools_menu(self):
        """Advanced security tools submenu"""
        while True:
            self.clear_screen()
            self.console.print(Panel(
                "Advanced Security Tools", 
                border_style="bold red"
            ))
            
            advanced_options = [
                "1. System Information",
                "2. Network Diagnostics",
                "3. SSL Certificate Check",
                "4. Domain Information",
                "5. Network Speed Test",
                "6. Advanced Port Scan",
                "7. File Hash Generator",
                "8. Network Mapping",
                "9. Basic Vulnerability Scan",
                "10. System Security Assessment",
                "11. Extended Security Tools",
                "12. Return to Main Menu"
            ]
            
            self.console.print(Panel(
                "\n".join(advanced_options),
                title="[bold magenta]Advanced Tools[/bold magenta]",
                border_style="bold blue"
            ))
            
            choice = input("\nEnter your choice (1-12): ")
            
            try:
                if choice == '1':
                    self.display_tool_results(
                        "System Information", 
                        self.advanced_tools.get_system_info()
                    )
                elif choice == '2':
                    target = input("Enter target IP (default: 8.8.8.8): ") or '8.8.8.8'
                    self.display_tool_results(
                        "Network Diagnostics", 
                        self.advanced_tools.run_network_diagnostics(target)
                    )
                elif choice == '3':
                    domain = input("Enter domain to check SSL certificate: ")
                    self.display_tool_results(
                        "SSL Certificate Check", 
                        self.advanced_tools.check_ssl_certificate(domain)
                    )
                elif choice == '4':
                    domain = input("Enter domain to get information: ")
                    self.display_tool_results(
                        "Domain Information", 
                        self.advanced_tools.get_domain_info(domain)
                    )
                elif choice == '5':
                    self.display_tool_results(
                        "Network Speed Test", 
                        self.advanced_tools.run_speed_test()
                    )
                elif choice == '6':
                    target = input("Enter target IP or network to scan: ")
                    self.display_tool_results(
                        "Advanced Port Scan", 
                        self.advanced_tools.advanced_port_scan(target)
                    )
                elif choice == '7':
                    file_path = input("Enter file path to generate hashes: ")
                    self.display_tool_results(
                        "File Hash Generator", 
                        self.advanced_tools.generate_file_hashes(file_path)
                    )
                elif choice == '8':
                    network = input("Enter network to map (default: 192.168.1.0/24): ") or '192.168.1.0/24'
                    self.display_tool_results(
                        "Network Mapping", 
                        self.advanced_tools.create_network_map(network)
                    )
                elif choice == '9':
                    target = input("Enter target for vulnerability scan: ")
                    self.display_tool_results(
                        "Basic Vulnerability Scan", 
                        self.advanced_tools.basic_vulnerability_scan(target)
                    )
                elif choice == '10':
                    self.display_tool_results(
                        "System Security Assessment", 
                        self.advanced_tools.system_security_assessment()
                    )
                elif choice == '11':
                    self.extended_security_tools_menu()
                elif choice == '12':
                    break
                else:
                    self.console.print("[bold red]Invalid choice. Try again.[/bold red]")
                
                input("\nPress Enter to continue...")
            except Exception as e:
                self.console.print(f"[bold red]Error: {e}[/bold red]")
                input("\nPress Enter to continue...")

    def extended_security_tools_menu(self):
        """Extended security tools submenu"""
        while True:
            self.clear_screen()
            self.console.print(Panel(
                "Extended Security Tools", 
                border_style="bold red"
            ))
            
            extended_options = [
                "1. Network Traffic Analyzer",
                "2. DNS Reconnaissance",
                "3. Web Technology Fingerprinter",
                "4. Password Strength Analyzer",
                "5. Encryption Toolkit",
                "6. System Integrity Check",
                "7. Threat Intelligence Lookup",
                "8. Wireless Network Scanner",
                "9. Specialized Security Tools",
                "10. Return to Advanced Tools Menu"
            ]
            
            self.console.print(Panel(
                "\n".join(extended_options),
                title="[bold magenta]Extended Security Tools[/bold magenta]",
                border_style="bold blue"
            ))
            
            choice = input("\nEnter your choice (1-10): ")
            
            try:
                if choice == '1':
                    interface = input("Enter network interface (default: eth0): ") or 'eth0'
                    self.display_tool_results(
                        "Network Traffic Analyzer", 
                        self.extended_tools.network_traffic_analyzer(interface)
                    )
                elif choice == '2':
                    domain = input("Enter domain for DNS reconnaissance: ")
                    self.display_tool_results(
                        "DNS Reconnaissance", 
                        self.extended_tools.dns_reconnaissance(domain)
                    )
                elif choice == '3':
                    url = input("Enter website URL for technology fingerprinting: ")
                    self.display_tool_results(
                        "Web Technology Fingerprinter", 
                        self.extended_tools.web_technology_fingerprinter(url)
                    )
                elif choice == '4':
                    password = input("Enter password to analyze strength: ")
                    self.display_tool_results(
                        "Password Strength Analyzer", 
                        self.extended_tools.password_strength_analyzer(password)
                    )
                elif choice == '5':
                    mode = input("Enter mode (generate/encrypt/decrypt): ")
                    self.display_tool_results(
                        "Encryption Toolkit", 
                        self.extended_tools.encryption_toolkit(mode)
                    )
                elif choice == '6':
                    self.display_tool_results(
                        "System Integrity Check", 
                        self.extended_tools.system_integrity_check()
                    )
                elif choice == '7':
                    target = input("Enter IP or domain for threat intelligence: ")
                    self.display_tool_results(
                        "Threat Intelligence Lookup", 
                        self.extended_tools.threat_intelligence_lookup(target)
                    )
                elif choice == '8':
                    self.display_tool_results(
                        "Wireless Network Scanner", 
                        self.extended_tools.wireless_network_scanner()
                    )
                elif choice == '9':
                    self.specialized_security_tools_menu()
                elif choice == '10':
                    break
                else:
                    self.console.print("[bold red]Invalid choice. Try again.[/bold red]")
                
                input("\nPress Enter to continue...")
            except Exception as e:
                self.console.print(f"[bold red]Error: {e}[/bold red]")
                input("\nPress Enter to continue...")

    def specialized_security_tools_menu(self):
        """Specialized security tools submenu"""
        while True:
            self.clear_screen()
            self.console.print(Panel(
                "Specialized Security Tools", 
                border_style="bold red"
            ))
            
            specialized_options = [
                "1. Forensic Metadata Extractor",
                "2. Network Geolocation Tracker",
                "3. Advanced Log Analyzer",
                "4. System Configuration Audit",
                "5. URL Reputation Checker",
                "6. SSL Certificate Analyzer",
                "7. Malware Signature Scanner",
                "8. Network Protocol Analyzer",
                "9. System Resource Forensics",
                "10. Comprehensive Security Toolkit",
                "11. Return to Extended Tools Menu"
            ]
            
            self.console.print(Panel(
                "\n".join(specialized_options),
                title="[bold magenta]Specialized Security Tools[/bold magenta]",
                border_style="bold blue"
            ))
            
            choice = input("\nEnter your choice (1-11): ")
            
            try:
                if choice == '1':
                    file_path = input("Enter file path for metadata extraction: ")
                    self.display_tool_results(
                        "Forensic Metadata Extractor", 
                        self.specialized_tools.forensic_metadata_extractor(file_path)
                    )
                elif choice == '2':
                    ip_address = input("Enter IP address (or leave blank for public IP): ") or None
                    self.display_tool_results(
                        "Network Geolocation Tracker", 
                        self.specialized_tools.network_geolocation_tracker(ip_address)
                    )
                elif choice == '3':
                    log_path = input("Enter log file path: ")
                    self.display_tool_results(
                        "Advanced Log Analyzer", 
                        self.specialized_tools.advanced_log_analyzer(log_path)
                    )
                elif choice == '4':
                    self.display_tool_results(
                        "System Configuration Audit", 
                        self.specialized_tools.system_configuration_audit()
                    )
                elif choice == '5':
                    url = input("Enter URL to check reputation: ")
                    self.display_tool_results(
                        "URL Reputation Checker", 
                        self.specialized_tools.url_reputation_checker(url)
                    )
                elif choice == '6':
                    domain = input("Enter domain for SSL certificate analysis: ")
                    self.display_tool_results(
                        "SSL Certificate Analyzer", 
                        self.specialized_tools.ssl_certificate_analyzer(domain)
                    )
                elif choice == '7':
                    directory_path = input("Enter directory path to scan for malware: ")
                    self.display_tool_results(
                        "Malware Signature Scanner", 
                        self.specialized_tools.malware_signature_scanner(directory_path)
                    )
                elif choice == '8':
                    interface = input("Enter network interface (default: eth0): ") or 'eth0'
                    self.display_tool_results(
                        "Network Protocol Analyzer", 
                        self.specialized_tools.network_protocol_analyzer(interface)
                    )
                elif choice == '9':
                    self.display_tool_results(
                        "System Resource Forensics", 
                        self.specialized_tools.system_resource_forensics()
                    )
                elif choice == '10':
                    self.comprehensive_security_toolkit_menu()
                elif choice == '11':
                    break
                else:
                    self.console.print("[bold red]Invalid choice. Try again.[/bold red]")
                
                input("\nPress Enter to continue...")
            except Exception as e:
                self.console.print(f"[bold red]Error: {e}[/bold red]")
                input("\nPress Enter to continue...")

    def comprehensive_security_toolkit_menu(self):
        """Comprehensive security toolkit submenu with categorized tools"""
        while True:
            self.clear_screen()
            self.console.print(Panel(
                "Comprehensive Security Toolkit", 
                border_style="bold red"
            ))
            
            toolkit_categories = [
                "1. Network Security Tools",
                "2. Web Security Tools",
                "3. Cryptography Tools",
                "4. System Security Tools",
                "5. Network Traffic Analysis",
                "6. Information Gathering Tools",
                "7. Vulnerability Assessment Tools",
                "8. Return to Specialized Tools Menu"
            ]
            
            self.console.print(Panel(
                "\n".join(toolkit_categories),
                title="[bold magenta]Security Tool Categories[/bold magenta]",
                border_style="bold blue"
            ))
            
            choice = input("\nEnter your choice (1-8): ")
            
            try:
                if choice == '1':
                    self.network_security_tools_menu()
                elif choice == '2':
                    self.web_security_tools_menu()
                elif choice == '3':
                    self.cryptography_tools_menu()
                elif choice == '4':
                    self.system_security_tools_menu()
                elif choice == '5':
                    self.network_traffic_analysis_menu()
                elif choice == '6':
                    self.information_gathering_tools_menu()
                elif choice == '7':
                    self.vulnerability_assessment_tools_menu()
                elif choice == '8':
                    break
                else:
                    self.console.print("[bold red]Invalid choice. Try again.[/bold red]")
                
                input("\nPress Enter to continue...")
            except Exception as e:
                self.console.print(f"[bold red]Error: {e}[/bold red]")
                input("\nPress Enter to continue...")

    def network_security_tools_menu(self):
        """Network Security Tools Submenu"""
        while True:
            self.clear_screen()
            self.console.print(Panel(
                "Network Security Tools", 
                border_style="bold blue"
            ))
            
            tools = [
                "1. Advanced Port Scanner",
                "2. DNS Reconnaissance",
                "3. Return to Toolkit Categories"
            ]
            
            self.console.print(Panel(
                "\n".join(tools),
                title="[bold green]Network Security Tools[/bold green]",
                border_style="bold cyan"
            ))
            
            choice = input("\nEnter your choice (1-3): ")
            
            try:
                if choice == '1':
                    target = input("Enter target for port scanning: ")
                    self.display_tool_results(
                        "Advanced Port Scanner", 
                        self.comprehensive_toolkit.NetworkSecurityTools.advanced_port_scanner(target)
                    )
                elif choice == '2':
                    domain = input("Enter domain for DNS reconnaissance: ")
                    self.display_tool_results(
                        "DNS Reconnaissance", 
                        self.comprehensive_toolkit.NetworkSecurityTools.dns_reconnaissance(domain)
                    )
                elif choice == '3':
                    break
                else:
                    self.console.print("[bold red]Invalid choice. Try again.[/bold red]")
                
                input("\nPress Enter to continue...")
            except Exception as e:
                self.console.print(f"[bold red]Error: {e}[/bold red]")
                input("\nPress Enter to continue...")

    def web_security_tools_menu(self):
        """Web Security Tools Submenu"""
        while True:
            self.clear_screen()
            self.console.print(Panel(
                "Web Security Tools", 
                border_style="bold blue"
            ))
            
            tools = [
                "1. Web Technology Detector",
                "2. Return to Toolkit Categories"
            ]
            
            self.console.print(Panel(
                "\n".join(tools),
                title="[bold green]Web Security Tools[/bold green]",
                border_style="bold cyan"
            ))
            
            choice = input("\nEnter your choice (1-2): ")
            
            try:
                if choice == '1':
                    url = input("Enter website URL: ")
                    self.display_tool_results(
                        "Web Technology Detector", 
                        self.comprehensive_toolkit.WebSecurityTools.web_technology_detector(url)
                    )
                elif choice == '2':
                    break
                else:
                    self.console.print("[bold red]Invalid choice. Try again.[/bold red]")
                
                input("\nPress Enter to continue...")
            except Exception as e:
                self.console.print(f"[bold red]Error: {e}[/bold red]")
                input("\nPress Enter to continue...")

    def cryptography_tools_menu(self):
        """Cryptography Tools Submenu"""
        while True:
            self.clear_screen()
            self.console.print(Panel(
                "Cryptography Tools", 
                border_style="bold blue"
            ))
            
            tools = [
                "1. Hash Generator",
                "2. Return to Toolkit Categories"
            ]
            
            self.console.print(Panel(
                "\n".join(tools),
                title="[bold green]Cryptography Tools[/bold green]",
                border_style="bold cyan"
            ))
            
            choice = input("\nEnter your choice (1-2): ")
            
            try:
                if choice == '1':
                    data = input("Enter data to hash: ")
                    self.display_tool_results(
                        "Hash Generator", 
                        self.comprehensive_toolkit.CryptographyTools.hash_generator(data)
                    )
                elif choice == '2':
                    break
                else:
                    self.console.print("[bold red]Invalid choice. Try again.[/bold red]")
                
                input("\nPress Enter to continue...")
            except Exception as e:
                self.console.print(f"[bold red]Error: {e}[/bold red]")
                input("\nPress Enter to continue...")

    def display_tool_results(self, tool_name, results):
        """Display tool results in a formatted panel"""
        self.clear_screen()
        self.console.print(Panel(
            "\n".join([f"{k}: {v}" for k, v in results.items()]),
            title=f"[bold green]{tool_name} Results[/bold green]",
            border_style="bold blue"
        ))

    def network_scan_menu(self):
        """Network scanning submenu"""
        self.clear_screen()
        self.console.print(Panel(
            "Network Port Scanner", 
            border_style="bold blue"
        ))
        
        try:
            target = input("Enter network to scan (e.g., 192.168.1.0/24): ")
            scanner = NetworkScanner(target)
            
            self.animated_loading("Scanning Network")
            scanner.scan_network()
        except Exception as e:
            self.console.print(f"[bold red]Error: {e}[/bold red]")
        
        input("\nPress Enter to continue...")

    def system_monitor_menu(self):
        """System monitoring submenu"""
        self.clear_screen()
        self.console.print(Panel(
            "System Resource Monitor", 
            border_style="bold green"
        ))
        
        print("Select Monitoring Mode:")
        print("1. System Information")
        print("2. Continuous Monitoring")
        
        choice = input("Enter your choice (1/2): ")
        
        if choice == '1':
            self.monitor.get_system_info()
        elif choice == '2':
            self.monitor.monitor_resources()
        else:
            self.console.print("[bold red]Invalid choice![/bold red]")
        
        input("\nPress Enter to continue...")

    def ip_intelligence_menu(self):
        """IP intelligence submenu"""
        self.clear_screen()
        self.console.print(Panel(
            "IP Intelligence", 
            border_style="bold magenta"
        ))
        
        ip = input("Enter IP Address to investigate: ")
        ip_intel = IPIntelligence(ip)
        
        print("\nSelect IP Intelligence Options:")
        print("1. Geolocation Information")
        print("2. DNS Lookup")
        print("3. Both")
        
        choice = input("Enter your choice (1/2/3): ")
        
        self.animated_loading("Gathering IP Intelligence")
        
        if choice == '1':
            ip_intel.get_ip_geolocation()
        elif choice == '2':
            ip_intel.dns_lookup()
        elif choice == '3':
            ip_intel.get_ip_geolocation()
            ip_intel.dns_lookup()
        else:
            self.console.print("[bold red]Invalid choice![/bold red]")
        
        input("\nPress Enter to continue...")

    def comprehensive_scan(self):
        """Perform a comprehensive security scan"""
        self.clear_screen()
        self.console.print(Panel(
            "Comprehensive Security Scan", 
            border_style="bold red"
        ))
        
        # Combine all scanning methods
        try:
            # Network Scan
            network = input("Enter network to scan (e.g., 192.168.1.0/24): ")
            network_scanner = NetworkScanner(network)
            
            # IP Intelligence
            ip = input("Enter IP for intelligence gathering: ")
            ip_intel = IPIntelligence(ip)
            
            # Perform scans with loading animations
            self.animated_loading("Performing Network Scan")
            network_scanner.scan_network()
            
            self.animated_loading("Gathering IP Intelligence")
            ip_intel.get_ip_geolocation()
            ip_intel.dns_lookup()
            
            # System Monitoring
            self.console.print("\n[bold yellow]System Resource Snapshot:[/bold yellow]")
            self.monitor.get_system_info()
        
        except Exception as e:
            self.console.print(f"[bold red]Comprehensive Scan Error: {e}[/bold red]")
        
        input("\nPress Enter to continue...")

    def exit_toolkit(self):
        """Exit the toolkit with a farewell message"""
        self.clear_screen()
        farewell = text2art("Goodbye!", font="small")
        self.console.print(Panel(
            Text(farewell, style="bold green"),
            border_style="bold cyan",
            title="[bold red]Security Toolkit[/bold red]"
        ))
        sys.exit(0)

def main():
    toolkit = SecurityToolkitUI()
    toolkit.main_menu()

if __name__ == "__main__":
    main()
