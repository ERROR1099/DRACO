import os
import re
import sys
import json
import uuid
import socket
import hashlib
import logging
import platform
import subprocess
import urllib.parse
from typing import Dict, List, Any
import requests
import psutil
import nmap
import whois
import dns.resolver
import scapy.all as scapy
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class ComprehensiveSecurityToolkit:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.INFO)

    class NetworkSecurityTools:
        @staticmethod
        def advanced_port_scanner(target, ports='1-1024'):
            """Advanced network port scanning"""
            try:
                nm = nmap.PortScanner()
                nm.scan(target, ports)
                
                scan_results = {}
                for host in nm.all_hosts():
                    host_details = {}
                    for proto in nm[host].all_protocols():
                        ports = nm[host][proto].keys()
                        port_info = {
                            port: {
                                'state': nm[host][proto][port]['state'],
                                'service': nm[host][proto][port].get('name', 'Unknown')
                            } for port in ports
                        }
                        host_details[proto] = port_info
                    scan_results[host] = host_details
                
                return scan_results
            except Exception as e:
                return {"error": str(e)}

        @staticmethod
        def dns_reconnaissance(domain):
            """Comprehensive DNS information gathering"""
            dns_info = {
                'A Records': [],
                'MX Records': [],
                'NS Records': [],
                'TXT Records': []
            }
            
            try:
                dns_info['A Records'] = [str(r) for r in dns.resolver.resolve(domain, 'A')]
                dns_info['MX Records'] = [str(r.exchange) for r in dns.resolver.resolve(domain, 'MX')]
                dns_info['NS Records'] = [str(r) for r in dns.resolver.resolve(domain, 'NS')]
                dns_info['TXT Records'] = [str(r) for r in dns.resolver.resolve(domain, 'TXT')]
                
                return dns_info
            except Exception as e:
                return {"error": str(e)}

    class WebSecurityTools:
        @staticmethod
        def web_technology_detector(url):
            """Detect web technologies and frameworks"""
            try:
                response = requests.get(url, timeout=10)
                technologies = {
                    'Server': response.headers.get('Server', 'Unknown'),
                    'X-Powered-By': response.headers.get('X-Powered-By', 'Unknown'),
                    'Frameworks': []
                }
                
                html = response.text.lower()
                framework_markers = {
                    'React': 'react' in html,
                    'Angular': 'ng-' in html,
                    'Vue.js': 'vue' in html,
                    'Django': 'django' in html,
                    'Flask': 'flask' in html
                }
                
                technologies['Frameworks'] = [
                    framework for framework, detected in framework_markers.items() if detected
                ]
                
                return technologies
            except Exception as e:
                return {"error": str(e)}

    class CryptographyTools:
        @staticmethod
        def hash_generator(data, algorithms=['md5', 'sha1', 'sha256']):
            """Generate multiple hash types"""
            hashes = {}
            for algo in algorithms:
                if algo == 'md5':
                    hashes['MD5'] = hashlib.md5(data.encode()).hexdigest()
                elif algo == 'sha1':
                    hashes['SHA1'] = hashlib.sha1(data.encode()).hexdigest()
                elif algo == 'sha256':
                    hashes['SHA256'] = hashlib.sha256(data.encode()).hexdigest()
            return hashes

    class SystemSecurityTools:
        @staticmethod
        def system_process_audit():
            """Comprehensive system process audit"""
            audit_data = {
                'running_processes': [],
                'system_info': {
                    'os': platform.system(),
                    'release': platform.release(),
                    'machine': platform.machine()
                }
            }
            
            for proc in psutil.process_iter(['pid', 'name', 'username', 'status']):
                audit_data['running_processes'].append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'user': proc.info['username'],
                    'status': proc.info['status']
                })
            
            return audit_data

    class NetworkTrafficAnalysis:
        @staticmethod
        def packet_capture(interface='eth0', packet_count=100):
            """Capture and analyze network packets"""
            try:
                packets = scapy.sniff(iface=interface, count=packet_count)
                
                packet_summary = {
                    'total_packets': len(packets),
                    'packet_types': {},
                    'source_ips': {},
                    'destination_ips': {}
                }
                
                for packet in packets:
                    if scapy.IP in packet:
                        src_ip = packet[scapy.IP].src
                        dst_ip = packet[scapy.IP].dst
                        
                        packet_summary['source_ips'][src_ip] = \
                            packet_summary['source_ips'].get(src_ip, 0) + 1
                        packet_summary['destination_ips'][dst_ip] = \
                            packet_summary['destination_ips'].get(dst_ip, 0) + 1
                
                return packet_summary
            except Exception as e:
                return {"error": str(e)}

    class InformationGatheringTools:
        @staticmethod
        def domain_whois_lookup(domain):
            """Perform WHOIS lookup for domain information"""
            try:
                domain_info = whois.whois(domain)
                return {
                    'domain_name': domain_info.domain_name,
                    'registrar': domain_info.registrar,
                    'creation_date': str(domain_info.creation_date),
                    'expiration_date': str(domain_info.expiration_date)
                }
            except Exception as e:
                return {"error": str(e)}

    class VulnerabilityAssessmentTools:
        @staticmethod
        def basic_vulnerability_scan(target):
            """Perform basic vulnerability scanning"""
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
                return {"error": str(e)}

def main():
    toolkit = ComprehensiveSecurityToolkit()
    
    # Example tool usage demonstrations
    print("Network Port Scanner:")
    print(toolkit.NetworkSecurityTools.advanced_port_scanner('scanme.nmap.org'))
    
    print("\nDomain WHOIS Lookup:")
    print(toolkit.InformationGatheringTools.domain_whois_lookup('google.com'))

if __name__ == "__main__":
    main()
