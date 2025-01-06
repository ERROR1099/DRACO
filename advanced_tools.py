import os
import sys
import socket
import requests
import whois
import ssl
import hashlib
import subprocess
import platform
import uuid
import psutil
import speedtest
import nmap
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from urllib.parse import urlparse

class AdvancedSecurityTools:
    def __init__(self):
        self.tools = {
            'system_info': self.get_system_info,
            'network_diagnostics': self.run_network_diagnostics,
            'ssl_checker': self.check_ssl_certificate,
            'domain_info': self.get_domain_info,
            'speed_test': self.run_speed_test,
            'port_scan': self.advanced_port_scan,
            'hash_generator': self.generate_file_hashes,
            'network_mapping': self.create_network_map,
            'vulnerability_scan': self.basic_vulnerability_scan,
            'system_security_check': self.system_security_assessment
        }

    def get_system_info(self):
        """Comprehensive system information gathering"""
        system_info = {
            'OS': platform.system(),
            'OS Version': platform.version(),
            'Machine': platform.machine(),
            'Processor': platform.processor(),
            'Python Version': platform.python_version(),
            'Unique Machine ID': str(uuid.getnode()),
            'Total RAM': f"{psutil.virtual_memory().total / (1024**3):.2f} GB",
            'Available RAM': f"{psutil.virtual_memory().available / (1024**3):.2f} GB",
            'CPU Cores': psutil.cpu_count(logical=False),
            'Total CPU Threads': psutil.cpu_count(logical=True)
        }
        return system_info

    def run_network_diagnostics(self, target='8.8.8.8'):
        """Advanced network diagnostics"""
        try:
            # Ping test
            ping_result = subprocess.run(['ping', '-c', '4', target], 
                                         capture_output=True, text=True)
            
            # Traceroute
            traceroute_result = subprocess.run(['traceroute', target], 
                                               capture_output=True, text=True)
            
            return {
                'Ping Results': ping_result.stdout,
                'Traceroute': traceroute_result.stdout
            }
        except Exception as e:
            return {'Error': str(e)}

    def check_ssl_certificate(self, domain):
        """SSL Certificate detailed analysis"""
        try:
            # Create an SSL context
            context = ssl.create_default_context()
            
            # Establish a connection
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                    # Get certificate
                    cert = secure_sock.getpeercert(binary_form=True)
                    x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                    
                    return {
                        'Subject': x509_cert.subject.rfc4514_string(),
                        'Issuer': x509_cert.issuer.rfc4514_string(),
                        'Version': x509_cert.version.name,
                        'Serial Number': x509_cert.serial_number,
                        'Not Valid Before': x509_cert.not_valid_before,
                        'Not Valid After': x509_cert.not_valid_after,
                        'Signature Algorithm': x509_cert.signature_algorithm_oid._name
                    }
        except Exception as e:
            return {'SSL Check Error': str(e)}

    def get_domain_info(self, domain):
        """Comprehensive domain information lookup"""
        try:
            domain_info = whois.whois(domain)
            return {
                'Domain Name': domain_info.domain_name,
                'Registrar': domain_info.registrar,
                'Creation Date': str(domain_info.creation_date),
                'Expiration Date': str(domain_info.expiration_date),
                'Name Servers': domain_info.name_servers
            }
        except Exception as e:
            return {'Domain Info Error': str(e)}

    def run_speed_test(self):
        """Comprehensive network speed test"""
        try:
            st = speedtest.Speedtest()
            
            return {
                'Download Speed': f"{st.download() / 1_000_000:.2f} Mbps",
                'Upload Speed': f"{st.upload() / 1_000_000:.2f} Mbps",
                'Ping': f"{st.results.ping} ms",
                'Server': st.get_best_server()
            }
        except Exception as e:
            return {'Speed Test Error': str(e)}

    def advanced_port_scan(self, target, ports=None):
        """Advanced network port scanning"""
        try:
            nm = nmap.PortScanner()
            
            if not ports:
                ports = '1-1024'  # Default port range
            
            nm.scan(target, ports)
            
            scan_results = {}
            for host in nm.all_hosts():
                host_info = {}
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    port_details = {}
                    for port in ports:
                        state = nm[host][proto][port]['state']
                        service = nm[host][proto][port].get('name', 'Unknown')
                        port_details[port] = {
                            'state': state,
                            'service': service
                        }
                    host_info[proto] = port_details
                scan_results[host] = host_info
            
            return scan_results
        except Exception as e:
            return {'Port Scan Error': str(e)}

    def generate_file_hashes(self, file_path):
        """Generate multiple hash types for a file"""
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
                return {
                    'MD5': hashlib.md5(file_data).hexdigest(),
                    'SHA1': hashlib.sha1(file_data).hexdigest(),
                    'SHA256': hashlib.sha256(file_data).hexdigest(),
                    'SHA512': hashlib.sha512(file_data).hexdigest()
                }
        except Exception as e:
            return {'Hash Generation Error': str(e)}

    def create_network_map(self, network='192.168.1.0/24'):
        """Create a comprehensive network map"""
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=network, arguments='-sn')
            
            network_map = {}
            for host in nm.all_hosts():
                try:
                    hostname = socket.gethostbyaddr(host)[0]
                except:
                    hostname = 'Unknown'
                
                network_map[host] = {
                    'hostname': hostname,
                    'status': nm[host].state()
                }
            
            return network_map
        except Exception as e:
            return {'Network Mapping Error': str(e)}

    def basic_vulnerability_scan(self, target):
        """Basic vulnerability assessment"""
        try:
            nm = nmap.PortScanner()
            nm.scan(target, arguments='--script vuln')
            
            vulnerabilities = {}
            for host in nm.all_hosts():
                host_vulns = {}
                for proto in nm[host].all_protocols():
                    vuln_scripts = nm[host][proto].get('script', {})
                    host_vulns[proto] = vuln_scripts
                vulnerabilities[host] = host_vulns
            
            return vulnerabilities
        except Exception as e:
            return {'Vulnerability Scan Error': str(e)}

    def system_security_assessment(self):
        """Comprehensive system security assessment"""
        assessment = {
            'Open Ports': list(psutil.net_connections()),
            'Running Processes': [
                {
                    'pid': p.pid,
                    'name': p.name(),
                    'status': p.status()
                } for p in psutil.process_iter(['pid', 'name', 'status'])
            ],
            'Firewall Status': self._check_firewall_status(),
            'Antivirus Status': self._check_antivirus()
        }
        return assessment

    def _check_firewall_status(self):
        """Check firewall status"""
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], 
                                        capture_output=True, text=True)
                return result.stdout
            elif platform.system() == 'Linux':
                result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
                return result.stdout
            elif platform.system() == 'Darwin':
                result = subprocess.run(['sudo', 'pfctl', '-s', 'info'], 
                                        capture_output=True, text=True)
                return result.stdout
        except Exception as e:
            return f"Firewall check error: {str(e)}"

    def _check_antivirus(self):
        """Check antivirus status"""
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(['powershell', 'Get-MpComputerStatus'], 
                                        capture_output=True, text=True)
                return result.stdout
            # Add more OS-specific antivirus checks
        except Exception as e:
            return f"Antivirus check error: {str(e)}"

def main():
    # Demonstration of tools
    security_tools = AdvancedSecurityTools()
    
    # Example usage of various tools
    print("System Information:")
    print(security_tools.get_system_info())
    
    print("\nNetwork Diagnostics:")
    print(security_tools.run_network_diagnostics())
    
    # Add more tool demonstrations as needed

if __name__ == "__main__":
    main()
