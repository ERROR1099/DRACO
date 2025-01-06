import os
import sys
import socket
import requests
import subprocess
import platform
import uuid
import psutil
import json
import base64
import hashlib
import re
import dns.resolver
import shodan
import censys.ipv4
import logging
from cryptography.fernet import Fernet
from urllib.parse import urlparse
from scapy.all import *
from typing import Dict, List, Any

class ExtendedSecurityTools:
    def __init__(self):
        # Configure logging
        logging.basicConfig(level=logging.INFO, 
                            format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

    def network_traffic_analyzer(self, interface='eth0', packet_count=100):
        """Capture and analyze network traffic"""
        try:
            packets = sniff(iface=interface, count=packet_count)
            
            traffic_summary = {
                'total_packets': len(packets),
                'packet_types': {},
                'source_ips': {},
                'destination_ips': {}
            }
            
            for packet in packets:
                # Analyze packet types
                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    
                    # Count packet types
                    packet_type = packet.summary().split()[0]
                    traffic_summary['packet_types'][packet_type] = \
                        traffic_summary['packet_types'].get(packet_type, 0) + 1
                    
                    # Track source and destination IPs
                    traffic_summary['source_ips'][src_ip] = \
                        traffic_summary['source_ips'].get(src_ip, 0) + 1
                    traffic_summary['destination_ips'][dst_ip] = \
                        traffic_summary['destination_ips'].get(dst_ip, 0) + 1
            
            return traffic_summary
        except Exception as e:
            self.logger.error(f"Network traffic analysis error: {e}")
            return {"error": str(e)}

    def dns_reconnaissance(self, domain):
        """Perform comprehensive DNS reconnaissance"""
        dns_info = {
            'A Records': [],
            'MX Records': [],
            'NS Records': [],
            'TXT Records': [],
            'CNAME Records': []
        }
        
        try:
            # A Records
            dns_info['A Records'] = [
                str(rdata) for rdata in dns.resolver.resolve(domain, 'A')
            ]
            
            # MX Records
            dns_info['MX Records'] = [
                str(rdata.exchange) for rdata in dns.resolver.resolve(domain, 'MX')
            ]
            
            # NS Records
            dns_info['NS Records'] = [
                str(rdata) for rdata in dns.resolver.resolve(domain, 'NS')
            ]
            
            # TXT Records
            dns_info['TXT Records'] = [
                str(rdata) for rdata in dns.resolver.resolve(domain, 'TXT')
            ]
            
            # CNAME Records
            try:
                dns_info['CNAME Records'] = [
                    str(rdata) for rdata in dns.resolver.resolve(domain, 'CNAME')
                ]
            except dns.resolver.NoAnswer:
                dns_info['CNAME Records'] = []
            
            return dns_info
        except Exception as e:
            self.logger.error(f"DNS reconnaissance error: {e}")
            return {"error": str(e)}

    def web_technology_fingerprinter(self, url):
        """Identify web technologies used by a website"""
        try:
            # Use requests to fetch headers and content
            response = requests.get(url, timeout=10)
            
            # Basic technology detection
            technologies = {
                'Server': response.headers.get('Server', 'Unknown'),
                'X-Powered-By': response.headers.get('X-Powered-By', 'Unknown'),
                'Content-Type': response.headers.get('Content-Type', 'Unknown')
            }
            
            # Check for common frameworks and technologies in HTML
            html_content = response.text.lower()
            tech_markers = {
                'React': 'react' in html_content,
                'Angular': 'ng-' in html_content,
                'Vue.js': 'vue' in html_content,
                'jQuery': 'jquery' in html_content,
                'Bootstrap': 'bootstrap' in html_content
            }
            
            technologies.update(tech_markers)
            
            return technologies
        except Exception as e:
            self.logger.error(f"Web technology fingerprinting error: {e}")
            return {"error": str(e)}

    def password_strength_analyzer(self, password):
        """Analyze password strength"""
        strength_criteria = {
            'length': len(password) >= 12,
            'uppercase': any(c.isupper() for c in password),
            'lowercase': any(c.islower() for c in password),
            'digits': any(c.isdigit() for c in password),
            'special_chars': any(not c.isalnum() for c in password)
        }
        
        # Calculate overall strength
        strength_score = sum(strength_criteria.values())
        
        return {
            'password': '*' * len(password),  # Mask actual password
            'length': len(password),
            'strength_criteria': strength_criteria,
            'strength_score': strength_score,
            'strength_level': self._get_strength_level(strength_score)
        }

    def _get_strength_level(self, score):
        """Determine password strength level"""
        if score <= 2:
            return 'Very Weak'
        elif score <= 3:
            return 'Weak'
        elif score <= 4:
            return 'Moderate'
        else:
            return 'Strong'

    def encryption_toolkit(self, mode='generate'):
        """Encryption and key generation toolkit"""
        if mode == 'generate':
            # Generate a new encryption key
            key = Fernet.generate_key()
            return {
                'encryption_key': base64.urlsafe_b64encode(key).decode(),
                'key_type': 'Fernet Symmetric Key'
            }
        elif mode == 'encrypt':
            # Example encryption (would typically take plaintext as input)
            key = Fernet.generate_key()
            f = Fernet(key)
            plaintext = b"Sample sensitive data"
            encrypted = f.encrypt(plaintext)
            return {
                'encrypted_data': base64.urlsafe_b64encode(encrypted).decode(),
                'key': base64.urlsafe_b64encode(key).decode()
            }
        elif mode == 'decrypt':
            # Example decryption (would typically take ciphertext and key as input)
            return {"message": "Decryption requires specific key and ciphertext"}

    def system_integrity_check(self):
        """Perform system integrity and security checks"""
        integrity_report = {
            'running_processes': [],
            'open_network_connections': [],
            'startup_programs': [],
            'system_logs': []
        }
        
        try:
            # Check running processes
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                integrity_report['running_processes'].append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'user': proc.info['username']
                })
            
            # Check network connections
            for conn in psutil.net_connections():
                integrity_report['open_network_connections'].append({
                    'fd': conn.fd,
                    'family': conn.family,
                    'type': conn.type,
                    'laddr': conn.laddr,
                    'raddr': conn.raddr,
                    'status': conn.status
                })
            
            # Check startup programs (Windows-specific)
            if platform.system() == 'Windows':
                startup_result = subprocess.run(
                    ['wmic', 'startup', 'get', 'caption,command'], 
                    capture_output=True, text=True
                )
                integrity_report['startup_programs'] = startup_result.stdout.split('\n')
            
            return integrity_report
        except Exception as e:
            self.logger.error(f"System integrity check error: {e}")
            return {"error": str(e)}

    def threat_intelligence_lookup(self, ip_or_domain):
        """Perform threat intelligence lookup"""
        try:
            # Note: This requires API keys which should be securely managed
            # Shodan example (requires SHODAN_API_KEY environment variable)
            shodan_api_key = os.environ.get('SHODAN_API_KEY')
            if shodan_api_key:
                api = shodan.Shodan(shodan_api_key)
                host = api.host(ip_or_domain)
                return {
                    'ip': host.get('ip_str'),
                    'organization': host.get('org', 'Unknown'),
                    'ports': host.get('ports', []),
                    'vulnerabilities': host.get('vulns', [])
                }
            
            # Censys example (requires CENSYS_API_ID and CENSYS_API_SECRET)
            censys_api_id = os.environ.get('CENSYS_API_ID')
            censys_api_secret = os.environ.get('CENSYS_API_SECRET')
            if censys_api_id and censys_api_secret:
                c = censys.ipv4.CensysIPv4(api_id=censys_api_id, api_secret=censys_api_secret)
                result = c.view(ip_or_domain)
                return {
                    'ip': result.get('ip'),
                    'protocols': result.get('protocols', []),
                    'location': result.get('location', {})
                }
            
            return {"error": "No threat intelligence API keys configured"}
        except Exception as e:
            self.logger.error(f"Threat intelligence lookup error: {e}")
            return {"error": str(e)}

    def wireless_network_scanner(self):
        """Scan and analyze wireless networks"""
        try:
            # This requires additional system tools and might need root/admin privileges
            if platform.system() == 'Linux':
                # Use iwlist for Linux
                result = subprocess.run(['sudo', 'iwlist', 'wlan0', 'scan'], 
                                        capture_output=True, text=True)
                networks = self._parse_iwlist_output(result.stdout)
            elif platform.system() == 'Darwin':
                # Use airport for macOS
                result = subprocess.run(['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s'], 
                                        capture_output=True, text=True)
                networks = self._parse_airport_output(result.stdout)
            elif platform.system() == 'Windows':
                # Use netsh for Windows
                result = subprocess.run(['netsh', 'wlan', 'show', 'networks'], 
                                        capture_output=True, text=True)
                networks = self._parse_netsh_output(result.stdout)
            else:
                return {"error": "Unsupported operating system"}
            
            return networks
        except Exception as e:
            self.logger.error(f"Wireless network scanning error: {e}")
            return {"error": str(e)}

    def _parse_iwlist_output(self, output):
        """Parse iwlist scan output for Linux"""
        networks = []
        current_network = {}
        for line in output.split('\n'):
            if 'Cell' in line:
                if current_network:
                    networks.append(current_network)
                current_network = {}
            
            if 'ESSID' in line:
                current_network['ssid'] = line.split(':')[1].strip('"')
            elif 'Address' in line:
                current_network['bssid'] = line.split(':')[1].strip()
            elif 'Channel' in line:
                current_network['channel'] = line.split(':')[1].strip()
            elif 'Quality' in line:
                current_network['signal_level'] = line.split('=')[1].split()[0]
        
        if current_network:
            networks.append(current_network)
        
        return networks

    def _parse_airport_output(self, output):
        """Parse airport scan output for macOS"""
        networks = []
        lines = output.split('\n')[1:]  # Skip header
        for line in lines:
            parts = line.split()
            if len(parts) >= 7:
                networks.append({
                    'ssid': parts[0],
                    'bssid': parts[1],
                    'rssi': parts[2],
                    'channel': parts[3],
                    'ht': parts[4],
                    'security': parts[5:]
                })
        return networks

    def _parse_netsh_output(self, output):
        """Parse netsh wlan show networks output for Windows"""
        networks = []
        current_network = {}
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('SSID'):
                current_network['ssid'] = line.split(':')[1].strip()
            elif line.startswith('Network type'):
                current_network['type'] = line.split(':')[1].strip()
            elif line.startswith('Authentication'):
                current_network['authentication'] = line.split(':')[1].strip()
            elif line.startswith('Encryption'):
                current_network['encryption'] = line.split(':')[1].strip()
            
            if len(current_network) == 4:
                networks.append(current_network)
                current_network = {}
        
        return networks

def main():
    # Demonstration of tools
    security_tools = ExtendedSecurityTools()
    
    # Example usage of various tools
    print("Network Traffic Analyzer:")
    print(security_tools.network_traffic_analyzer())
    
    print("\nDNS Reconnaissance:")
    print(security_tools.dns_reconnaissance('example.com'))
    
    # Add more tool demonstrations as needed

if __name__ == "__main__":
    main()
