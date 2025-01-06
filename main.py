#!/usr/bin/env python3

import os
import sys
import time
import threading
from typing import Dict, Any, Callable

# Import core components
from src.core.config_manager import ConfigManager
from src.core.base_tool import ToolRegistry
from src.utils.logging_handler import LoggingHandler
from src.utils.error_handler import ErrorHandler, SecurityToolkitError

# Import tool categories
from network_scanner import NetworkScanner
from system_monitor import SystemMonitor
from ip_info import IPIntelligence
from advanced_tools import AdvancedSecurityTools
from extended_security_tools import ExtendedSecurityTools
from specialized_security_tools import SpecializedSecurityTools
from comprehensive_security_toolkit import ComprehensiveSecurityToolkit

DRACO_LOGO = '''
      /\    ___
     //\\  /\--\\
    (    \\/  /  \\
     \\      /   /
      \\____/---/
       \\   \\  /
        \\___\\/

🐉 DRACO: Dynamic Reconnaissance 
and Cybersecurity Orchestrator
'''

def print_banner():
    """
    Print the DRACO ASCII art banner
    """
    print(DRACO_LOGO)

class SecurityToolkitUI:
    def __init__(self):
        # Initialize logging and configuration
        self.config_manager = ConfigManager()
        self.logger = LoggingHandler.get_logger('SecurityToolkitUI')
        
        # Initialize tool modules
        self.tools = {
            'network_scanner': NetworkScanner(),
            'system_monitor': SystemMonitor(),
            'ip_info': IPIntelligence(),
            'advanced_tools': AdvancedSecurityTools(),
            'extended_tools': ExtendedSecurityTools(),
            'specialized_tools': SpecializedSecurityTools(),
            'comprehensive_toolkit': ComprehensiveSecurityToolkit()
        }
        
        # Register tools in the central registry
        self._register_tools()
    
    def _register_tools(self):
        """Register all tools in the central tool registry"""
        for name, tool in self.tools.items():
            ToolRegistry.register_tool(tool)
    
    def display_main_menu(self):
        """Display the main menu of the security toolkit"""
        while True:
            self._clear_screen()
            print("\n=== Advanced Security Toolkit ===")
            print("1. Network Security Tools")
            print("2. System Monitoring Tools")
            print("3. IP Intelligence Tools")
            print("4. Advanced Security Tools")
            print("5. Extended Security Tools")
            print("6. Specialized Security Tools")
            print("7. Comprehensive Security Toolkit")
            print("8. Configuration Management")
            print("9. Performance Metrics")
            print("0. Exit")
            
            choice = input("\nEnter your choice: ")
            
            try:
                if choice == '1':
                    self._network_tools_menu()
                elif choice == '2':
                    self._system_monitoring_menu()
                elif choice == '3':
                    self._ip_intelligence_menu()
                elif choice == '4':
                    self._advanced_tools_menu()
                elif choice == '5':
                    self._extended_tools_menu()
                elif choice == '6':
                    self._specialized_tools_menu()
                elif choice == '7':
                    self._comprehensive_toolkit_menu()
                elif choice == '8':
                    self._configuration_management()
                elif choice == '9':
                    self._performance_metrics()
                elif choice == '0':
                    self._exit_toolkit()
                else:
                    print("Invalid choice. Please try again.")
            except Exception as e:
                ErrorHandler.handle_error(e)
                input("Press Enter to continue...")
    
    def _network_tools_menu(self):
        """Network security tools submenu"""
        while True:
            self._clear_screen()
            print("\n=== Network Security Tools ===")
            print("1. Port Scanner")
            print("2. Network Diagnostics")
            print("0. Return to Main Menu")
            
            choice = input("\nEnter your choice: ")
            
            try:
                if choice == '1':
                    target = input("Enter target IP or hostname: ")
                    result = self.tools['network_scanner'].scan_ports(target)
                    self._display_results(result)
                elif choice == '2':
                    interface = input("Enter network interface (default: eth0): ") or 'eth0'
                    result = self.tools['network_scanner'].network_diagnostics(interface)
                    self._display_results(result)
                elif choice == '0':
                    break
                else:
                    print("Invalid choice. Please try again.")
                
                input("Press Enter to continue...")
            except Exception as e:
                ErrorHandler.handle_error(e)
    
    def _system_monitoring_menu(self):
        """System monitoring tools submenu"""
        while True:
            self._clear_screen()
            print("\n=== System Monitoring Tools ===")
            print("1. Resource Usage")
            print("2. Process Monitor")
            print("3. System Health Check")
            print("0. Return to Main Menu")
            
            choice = input("\nEnter your choice: ")
            
            try:
                if choice == '1':
                    result = self.tools['system_monitor'].get_resource_usage()
                    self._display_results(result)
                elif choice == '2':
                    result = self.tools['system_monitor'].list_processes()
                    self._display_results(result)
                elif choice == '3':
                    result = self.tools['system_monitor'].system_health_check()
                    self._display_results(result)
                elif choice == '0':
                    break
                else:
                    print("Invalid choice. Please try again.")
                
                input("Press Enter to continue...")
            except Exception as e:
                ErrorHandler.handle_error(e)
    
    def _ip_intelligence_menu(self):
        """IP intelligence tools submenu"""
        while True:
            self._clear_screen()
            print("\n=== IP Intelligence Tools ===")
            print("1. IP Geolocation")
            print("2. DNS Lookup")
            print("3. Reverse IP Lookup")
            print("0. Return to Main Menu")
            
            choice = input("\nEnter your choice: ")
            
            try:
                if choice == '1':
                    ip = input("Enter IP address: ")
                    result = self.tools['ip_info'].get_ip_geolocation(ip)
                    self._display_results(result)
                elif choice == '2':
                    domain = input("Enter domain: ")
                    result = self.tools['ip_info'].dns_lookup(domain)
                    self._display_results(result)
                elif choice == '3':
                    ip = input("Enter IP address: ")
                    result = self.tools['ip_info'].reverse_ip_lookup(ip)
                    self._display_results(result)
                elif choice == '0':
                    break
                else:
                    print("Invalid choice. Please try again.")
                
                input("Press Enter to continue...")
            except Exception as e:
                ErrorHandler.handle_error(e)
    
    def _advanced_tools_menu(self):
        """Advanced security tools submenu"""
        while True:
            self._clear_screen()
            print("\n=== Advanced Security Tools ===")
            print("1. System Information Gathering")
            print("2. Network Diagnostics")
            print("3. Security Vulnerability Scan")
            print("0. Return to Main Menu")
            
            choice = input("\nEnter your choice: ")
            
            try:
                if choice == '1':
                    result = self.tools['advanced_tools'].system_info_gathering()
                    self._display_results(result)
                elif choice == '2':
                    target = input("Enter target (IP/hostname): ")
                    result = self.tools['advanced_tools'].network_diagnostics(target)
                    self._display_results(result)
                elif choice == '3':
                    target = input("Enter target for vulnerability scan: ")
                    result = self.tools['advanced_tools'].vulnerability_scan(target)
                    self._display_results(result)
                elif choice == '0':
                    break
                else:
                    print("Invalid choice. Please try again.")
                
                input("Press Enter to continue...")
            except Exception as e:
                ErrorHandler.handle_error(e)
    
    def _extended_tools_menu(self):
        """Extended security tools submenu"""
        while True:
            self._clear_screen()
            print("\n=== Extended Security Tools ===")
            print("1. Network Traffic Analysis")
            print("2. DNS Reconnaissance")
            print("3. Web Technology Fingerprinting")
            print("0. Return to Main Menu")
            
            choice = input("\nEnter your choice: ")
            
            try:
                if choice == '1':
                    interface = input("Enter network interface: ")
                    result = self.tools['extended_tools'].network_traffic_analyzer(interface)
                    self._display_results(result)
                elif choice == '2':
                    domain = input("Enter domain for reconnaissance: ")
                    result = self.tools['extended_tools'].dns_reconnaissance(domain)
                    self._display_results(result)
                elif choice == '3':
                    url = input("Enter website URL: ")
                    result = self.tools['extended_tools'].web_technology_fingerprinter(url)
                    self._display_results(result)
                elif choice == '0':
                    break
                else:
                    print("Invalid choice. Please try again.")
                
                input("Press Enter to continue...")
            except Exception as e:
                ErrorHandler.handle_error(e)
    
    def _specialized_tools_menu(self):
        """Specialized security tools submenu"""
        while True:
            self._clear_screen()
            print("\n=== Specialized Security Tools ===")
            print("1. Forensic Metadata Extractor")
            print("2. Network Geolocation Tracker")
            print("3. Advanced Log Analyzer")
            print("0. Return to Main Menu")
            
            choice = input("\nEnter your choice: ")
            
            try:
                if choice == '1':
                    file_path = input("Enter file path for metadata extraction: ")
                    result = self.tools['specialized_tools'].forensic_metadata_extractor(file_path)
                    self._display_results(result)
                elif choice == '2':
                    ip = input("Enter IP address (or leave blank for public IP): ") or None
                    result = self.tools['specialized_tools'].network_geolocation_tracker(ip)
                    self._display_results(result)
                elif choice == '3':
                    log_path = input("Enter log file path: ")
                    result = self.tools['specialized_tools'].advanced_log_analyzer(log_path)
                    self._display_results(result)
                elif choice == '0':
                    break
                else:
                    print("Invalid choice. Please try again.")
                
                input("Press Enter to continue...")
            except Exception as e:
                ErrorHandler.handle_error(e)
    
    def _comprehensive_toolkit_menu(self):
        """Comprehensive security toolkit submenu"""
        while True:
            self._clear_screen()
            print("\n=== Comprehensive Security Toolkit ===")
            print("1. Network Port Scanner")
            print("2. Web Technology Detector")
            print("3. Hash Generator")
            print("0. Return to Main Menu")
            
            choice = input("\nEnter your choice: ")
            
            try:
                if choice == '1':
                    target = input("Enter target for port scanning: ")
                    result = self.tools['comprehensive_toolkit'].NetworkSecurityTools.advanced_port_scanner(target)
                    self._display_results(result)
                elif choice == '2':
                    url = input("Enter website URL: ")
                    result = self.tools['comprehensive_toolkit'].WebSecurityTools.web_technology_detector(url)
                    self._display_results(result)
                elif choice == '3':
                    data = input("Enter data to hash: ")
                    result = self.tools['comprehensive_toolkit'].CryptographyTools.hash_generator(data)
                    self._display_results(result)
                elif choice == '0':
                    break
                else:
                    print("Invalid choice. Please try again.")
                
                input("Press Enter to continue...")
            except Exception as e:
                ErrorHandler.handle_error(e)
    
    def _configuration_management(self):
        """Configuration management interface"""
        while True:
            self._clear_screen()
            print("\n=== Configuration Management ===")
            print("1. View Current Configuration")
            print("2. Update Configuration")
            print("0. Return to Main Menu")
            
            choice = input("\nEnter your choice: ")
            
            try:
                if choice == '1':
                    config = self.config_manager.get_config()
                    print("\nCurrent Configuration:")
                    for key, value in config.items():
                        print(f"{key}: {value}")
                elif choice == '2':
                    key = input("Enter configuration key to update: ")
                    value = input("Enter new value: ")
                    self.config_manager.update_config({key: value})
                    print("Configuration updated successfully.")
                elif choice == '0':
                    break
                else:
                    print("Invalid choice. Please try again.")
                
                input("Press Enter to continue...")
            except Exception as e:
                ErrorHandler.handle_error(e)
    
    def _performance_metrics(self):
        """Performance metrics and system diagnostics"""
        self._clear_screen()
        print("\n=== Performance Metrics ===")
        
        try:
            # Collect performance data from various tools
            system_metrics = self.tools['system_monitor'].get_resource_usage()
            network_metrics = self.tools['network_scanner'].network_performance()
            
            print("\nSystem Resource Usage:")
            for key, value in system_metrics.items():
                print(f"{key}: {value}")
            
            print("\nNetwork Performance:")
            for key, value in network_metrics.items():
                print(f"{key}: {value}")
        
        except Exception as e:
            ErrorHandler.handle_error(e)
        
        input("\nPress Enter to return to Main Menu...")
    
    def _exit_toolkit(self):
        """Gracefully exit the security toolkit"""
        print("\nThank you for using the Advanced Security Toolkit!")
        print("Remember to use these tools ethically and responsibly.")
        sys.exit(0)
    
    def _clear_screen(self):
        """Clear console screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def _display_results(self, results: Dict[str, Any]):
        """
        Display tool execution results in a formatted manner
        
        Args:
            results (Dict[str, Any]): Results from tool execution
        """
        if not results:
            print("No results to display.")
            return
        
        print("\n=== Tool Results ===")
        for key, value in results.items():
            print(f"{key}: {value}")

def main():
    """Main entry point for the security toolkit"""
    print_banner()
    try:
        toolkit = SecurityToolkitUI()
        toolkit.display_main_menu()
    except Exception as e:
        ErrorHandler.handle_error(e)

if __name__ == "__main__":
    main()
