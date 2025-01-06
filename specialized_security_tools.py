import os
import re
import json
import time
import socket
import hashlib
import logging
import platform
import subprocess
import urllib.parse
import xml.etree.ElementTree as ET
from typing import Dict, List, Any
import requests
import psutil
import pytz
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

class SpecializedSecurityTools:
    def __init__(self):
        # Configure logging
        logging.basicConfig(level=logging.INFO, 
                            format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

    def forensic_metadata_extractor(self, file_path):
        """Extract comprehensive metadata from files"""
        try:
            # Basic file metadata
            stat = os.stat(file_path)
            metadata = {
                'filename': os.path.basename(file_path),
                'full_path': os.path.abspath(file_path),
                'file_size': stat.st_size,
                'created_time': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modified_time': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'accessed_time': datetime.fromtimestamp(stat.st_atime).isoformat(),
                'permissions': oct(stat.st_mode)[-3:]
            }

            # File type specific extraction
            file_ext = os.path.splitext(file_path)[1].lower()
            
            # Image metadata (requires Pillow)
            if file_ext in ['.jpg', '.jpeg', '.png', '.gif']:
                from PIL import Image
                from PIL.ExifTags import TAGS
                img = Image.open(file_path)
                exif_data = img._getexif()
                if exif_data:
                    metadata['exif'] = {
                        TAGS.get(tag, tag): value 
                        for tag, value in exif_data.items()
                    }

            # PDF metadata
            if file_ext == '.pdf':
                import PyPDF2
                with open(file_path, 'rb') as pdf_file:
                    pdf_reader = PyPDF2.PdfReader(pdf_file)
                    metadata['pdf_metadata'] = pdf_reader.metadata

            return metadata
        except Exception as e:
            self.logger.error(f"Metadata extraction error: {e}")
            return {"error": str(e)}

    def network_geolocation_tracker(self, ip_address=None):
        """Advanced IP geolocation and network information"""
        try:
            # If no IP provided, use public IP
            if not ip_address:
                ip_address = requests.get('https://api.ipify.org').text

            # Multiple geolocation sources
            sources = [
                f"https://ipapi.co/{ip_address}/json/",
                f"https://ip-api.com/json/{ip_address}"
            ]

            geolocation_data = {}
            for source in sources:
                try:
                    response = requests.get(source, timeout=5)
                    geolocation_data[source] = response.json()
                except Exception as e:
                    geolocation_data[source] = {"error": str(e)}

            # Traceroute information
            try:
                traceroute = subprocess.run(['traceroute', ip_address], 
                                            capture_output=True, 
                                            text=True, 
                                            timeout=10)
                geolocation_data['traceroute'] = traceroute.stdout
            except Exception:
                geolocation_data['traceroute'] = "Traceroute failed"

            return geolocation_data
        except Exception as e:
            self.logger.error(f"Geolocation tracking error: {e}")
            return {"error": str(e)}

    def advanced_log_analyzer(self, log_path):
        """Comprehensive log file analysis"""
        try:
            log_analysis = {
                'total_lines': 0,
                'error_count': 0,
                'warning_count': 0,
                'unique_ips': set(),
                'timestamp_range': {},
                'log_entries': []
            }

            with open(log_path, 'r') as log_file:
                for line in log_file:
                    log_analysis['total_lines'] += 1
                    
                    # Basic pattern matching
                    if 'error' in line.lower():
                        log_analysis['error_count'] += 1
                    
                    if 'warning' in line.lower():
                        log_analysis['warning_count'] += 1
                    
                    # IP extraction
                    ip_matches = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
                    log_analysis['unique_ips'].update(ip_matches)

                    # Timestamp extraction
                    timestamp_match = re.search(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', line)
                    if timestamp_match:
                        timestamp = timestamp_match.group(0)
                        log_analysis['timestamp_range'][timestamp] = line.strip()

            # Convert unique IPs to list
            log_analysis['unique_ips'] = list(log_analysis['unique_ips'])

            return log_analysis
        except Exception as e:
            self.logger.error(f"Log analysis error: {e}")
            return {"error": str(e)}

    def system_configuration_audit(self):
        """Comprehensive system configuration audit"""
        audit_report = {
            'os_info': {},
            'hardware_info': {},
            'network_config': {},
            'security_settings': {}
        }

        try:
            # OS Information
            audit_report['os_info'] = {
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor()
            }

            # Hardware Information
            audit_report['hardware_info'] = {
                'cpu_count': psutil.cpu_count(logical=False),
                'total_memory': f"{psutil.virtual_memory().total / (1024**3):.2f} GB",
                'disk_partitions': [
                    {
                        'device': p.device,
                        'mountpoint': p.mountpoint,
                        'fstype': p.fstype
                    } for p in psutil.disk_partitions()
                ]
            }

            # Network Configuration
            if platform.system() == 'Windows':
                # Windows network config
                netsh_result = subprocess.run(['netsh', 'interface', 'ip', 'show', 'config'], 
                                              capture_output=True, text=True)
                audit_report['network_config']['windows_config'] = netsh_result.stdout
            elif platform.system() == 'Linux':
                # Linux network config
                ifconfig_result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
                audit_report['network_config']['linux_config'] = ifconfig_result.stdout

            # Security Settings
            audit_report['security_settings'] = {
                'active_connections': [
                    {
                        'fd': conn.fd,
                        'family': conn.family,
                        'type': conn.type,
                        'laddr': conn.laddr,
                        'raddr': conn.raddr,
                        'status': conn.status
                    } for conn in psutil.net_connections()
                ]
            }

            return audit_report
        except Exception as e:
            self.logger.error(f"System configuration audit error: {e}")
            return {"error": str(e)}

    def url_reputation_checker(self, url):
        """Check URL reputation and potential threats"""
        try:
            # Validate URL
            parsed_url = urllib.parse.urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                return {"error": "Invalid URL format"}

            # Multiple reputation and safety checking services
            reputation_sources = [
                f"https://www.virustotal.com/vtapi/v2/url/report?apikey=YOUR_VIRUSTOTAL_API_KEY&resource={url}",
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key=YOUR_GOOGLE_SAFE_BROWSING_API_KEY"
            ]

            reputation_results = {}
            for source in reputation_sources:
                try:
                    response = requests.get(source, timeout=10)
                    reputation_results[source] = response.json()
                except Exception as e:
                    reputation_results[source] = {"error": str(e)}

            # Additional checks
            reputation_results['domain_info'] = {
                'domain': parsed_url.netloc,
                'scheme': parsed_url.scheme
            }

            return reputation_results
        except Exception as e:
            self.logger.error(f"URL reputation check error: {e}")
            return {"error": str(e)}

    def ssl_certificate_analyzer(self, domain):
        """Comprehensive SSL/TLS certificate analysis"""
        try:
            # Establish SSL connection
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                    # Get certificate
                    cert = secure_sock.getpeercert(binary_form=True)
                    x509_cert = x509.load_der_x509_certificate(cert, default_backend())

                    # Certificate details
                    cert_analysis = {
                        'subject': x509_cert.subject.rfc4514_string(),
                        'issuer': x509_cert.issuer.rfc4514_string(),
                        'version': x509_cert.version.name,
                        'serial_number': x509_cert.serial_number,
                        'not_valid_before': x509_cert.not_valid_before.isoformat(),
                        'not_valid_after': x509_cert.not_valid_after.isoformat(),
                        'signature_algorithm': x509_cert.signature_algorithm_oid._name,
                        'public_key_type': x509_cert.public_key().public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        ).decode()
                    }

                    return cert_analysis
        except Exception as e:
            self.logger.error(f"SSL certificate analysis error: {e}")
            return {"error": str(e)}

    def malware_signature_scanner(self, directory_path):
        """Scan directory for potential malware signatures"""
        try:
            malware_scan_results = {
                'total_files_scanned': 0,
                'suspicious_files': [],
                'malware_signatures': []
            }

            # Basic malware signature patterns
            malware_signatures = [
                r'eval\(base64_decode',  # PHP webshell
                r'cmd\.exe',             # Windows command execution
                r'/bin/bash',             # Unix shell execution
                r'wget\s+http',           # Potential download
                r'curl\s+-O',             # Potential download
            ]

            # Walk through directory
            for root, _, files in os.walk(directory_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    malware_scan_results['total_files_scanned'] += 1

                    try:
                        with open(file_path, 'r', errors='ignore') as f:
                            content = f.read()
                            
                            # Check for malware signatures
                            for signature in malware_signatures:
                                if re.search(signature, content, re.IGNORECASE):
                                    malware_scan_results['suspicious_files'].append(file_path)
                                    malware_scan_results['malware_signatures'].append({
                                        'file': file_path,
                                        'signature': signature
                                    })
                    except Exception as file_error:
                        self.logger.warning(f"Error scanning {file_path}: {file_error}")

            return malware_scan_results
        except Exception as e:
            self.logger.error(f"Malware signature scanning error: {e}")
            return {"error": str(e)}

    def network_protocol_analyzer(self, interface='eth0', packet_count=100):
        """Advanced network protocol analysis"""
        try:
            from scapy.all import sniff, IP, TCP, UDP

            protocol_stats = {
                'total_packets': 0,
                'protocols': {},
                'source_ips': {},
                'destination_ips': {},
                'ports': {}
            }

            def packet_callback(packet):
                protocol_stats['total_packets'] += 1

                # Protocol analysis
                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst

                    # Track source and destination IPs
                    protocol_stats['source_ips'][src_ip] = \
                        protocol_stats['source_ips'].get(src_ip, 0) + 1
                    protocol_stats['destination_ips'][dst_ip] = \
                        protocol_stats['destination_ips'].get(dst_ip, 0) + 1

                    # Protocol tracking
                    if TCP in packet:
                        proto = 'TCP'
                        port = packet[TCP].dport
                    elif UDP in packet:
                        proto = 'UDP'
                        port = packet[UDP].dport
                    else:
                        proto = 'Other'
                        port = 0

                    protocol_stats['protocols'][proto] = \
                        protocol_stats['protocols'].get(proto, 0) + 1
                    protocol_stats['ports'][port] = \
                        protocol_stats['ports'].get(port, 0) + 1

            # Capture packets
            sniff(iface=interface, prn=packet_callback, count=packet_count)

            return protocol_stats
        except Exception as e:
            self.logger.error(f"Network protocol analysis error: {e}")
            return {"error": str(e)}

    def system_resource_forensics(self):
        """Comprehensive system resource forensic analysis"""
        forensic_report = {
            'process_analysis': [],
            'memory_map': [],
            'open_files': [],
            'network_connections': []
        }

        try:
            # Process Analysis
            for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'create_time']):
                try:
                    forensic_report['process_analysis'].append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'username': proc.info['username'],
                        'status': proc.info['status'],
                        'start_time': datetime.fromtimestamp(proc.info['create_time']).isoformat()
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

            # Memory Mapping
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    memory_maps = proc.memory_maps()
                    for mmap in memory_maps:
                        forensic_report['memory_map'].append({
                            'pid': proc.pid,
                            'process_name': proc.name(),
                            'path': mmap.path,
                            'rss': mmap.rss
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # Open Files
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    open_files = proc.open_files()
                    for file in open_files:
                        forensic_report['open_files'].append({
                            'pid': proc.pid,
                            'process_name': proc.name(),
                            'path': file.path
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # Network Connections
            for conn in psutil.net_connections():
                forensic_report['network_connections'].append({
                    'fd': conn.fd,
                    'family': conn.family,
                    'type': conn.type,
                    'laddr': conn.laddr,
                    'raddr': conn.raddr,
                    'status': conn.status
                })

            return forensic_report
        except Exception as e:
            self.logger.error(f"System resource forensics error: {e}")
            return {"error": str(e)}

def main():
    # Demonstration of tools
    security_tools = SpecializedSecurityTools()
    
    # Example usage of various tools
    print("Forensic Metadata Extractor:")
    print(security_tools.forensic_metadata_extractor('/path/to/file'))
    
    print("\nNetwork Geolocation Tracker:")
    print(security_tools.network_geolocation_tracker())

if __name__ == "__main__":
    main()
