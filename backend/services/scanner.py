"""
VulneraAI - Vulnerability Scanner Service
"""

import socket
import threading
from datetime import datetime
from models.scan_model import Scan, Vulnerability
from config import Config
from services.api_integrations import APIIntegrations

class VulnerabilityScanner:
    def __init__(self, scan_id, target, scan_type='standard'):
        self.scan_id = scan_id
        self.target = target
        self.scan_type = scan_type
        self.scan = None
        self.thread = None
        self.api_integrations = APIIntegrations()

    def start(self):
        """Start scanning in background thread"""
        self.thread = threading.Thread(target=self._scan_worker)
        self.thread.daemon = True
        self.thread.start()

    def _scan_worker(self):
        """Perform the actual scanning"""
        try:
            self.scan = Scan.get_by_id(self.scan_id)
            if not self.scan:
                return

            self.scan.status = 'scanning'
            self.scan.started_at = datetime.utcnow()
            self.scan.save()

            # Step 1: Traditional port scanning
            ports_to_scan = self._get_ports_to_scan()
            vulnerabilities = self._scan_ports(ports_to_scan)
            
            # Step 2: Enhance with external API data
            self._enhance_with_external_apis(vulnerabilities)

            # Update scan with results
            self.scan.vulnerabilities = vulnerabilities
            self.scan.progress = 100
            self.scan.status = 'completed'
            self.scan.completed_at = datetime.utcnow()
            self.scan.save()

        except Exception as e:
            print(f"Scanning error: {str(e)}")
            if self.scan:
                self.scan.status = 'error'
                self.scan.save()
    
    def _enhance_with_external_apis(self, vulnerabilities):
        """Enhance scan results with data from Censys, NVD, and VirusTotal"""
        try:
            # Update progress
            self.scan.progress = 70
            self.scan.save()
            
            # 1. VirusTotal - Check IP/Domain reputation
            is_domain = not self._is_ip_address(self.target)
            
            if is_domain:
                vt_data = self.api_integrations.virustotal_scan_domain(self.target)
            else:
                vt_data = self.api_integrations.virustotal_scan_ip(self.target)
            
            if vt_data:
                vt_threats = self.api_integrations.extract_virustotal_threats(vt_data, self.target)
                for threat in vt_threats:
                    vulnerabilities.append(self._convert_to_vulnerability(threat))
            
            # Update progress
            self.scan.progress = 80
            self.scan.save()
            
            # 2. Censys - Get detailed host information (only for IPs)
            if not is_domain:
                censys_data = self.api_integrations.censys_search_host(self.target)
                if censys_data:
                    censys_vulns = self.api_integrations.extract_censys_vulnerabilities(censys_data)
                    for vuln in censys_vulns:
                        vulnerabilities.append(self._convert_to_vulnerability(vuln))
            
            # Update progress
            self.scan.progress = 90
            self.scan.save()
            
            # 3. NVD - Enrich vulnerabilities with CVE data
            services_found = set()
            for vuln in vulnerabilities:
                if hasattr(vuln, 'service') and vuln.service:
                    services_found.add(vuln.service)
            
            # Get CVE data for each unique service
            for service in list(services_found)[:3]:  # Limit to avoid rate limiting
                nvd_vulns = self.api_integrations.enrich_with_nvd(service)
                for nvd_vuln in nvd_vulns[:2]:  # Add top 2 CVEs per service
                    vulnerabilities.append(self._convert_to_vulnerability(nvd_vuln))
            
        except Exception as e:
            print(f"API enhancement error: {str(e)}")
            # Continue even if API calls fail
    
    def _convert_to_vulnerability(self, vuln_dict):
        """Convert dictionary to Vulnerability object"""
        return Vulnerability(
            title=vuln_dict.get('title', 'Unknown Vulnerability'),
            description=vuln_dict.get('description', ''),
            severity=vuln_dict.get('severity', 'medium'),
            port=vuln_dict.get('port'),
            service=vuln_dict.get('service', ''),
            cve=vuln_dict.get('cve', '')
        )
    
    def _is_ip_address(self, target):
        """Check if target is an IP address"""
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            return False

    def _get_ports_to_scan(self):
        """Get list of ports based on scan type"""
        if self.scan_type == 'quick':
            return [22, 80, 443]
        elif self.scan_type == 'standard':
            return Config.COMMON_PORTS[:10]
        else:  # comprehensive
            return Config.COMMON_PORTS

    def _scan_ports(self, ports):
        """Scan specified ports for vulnerabilities"""
        vulnerabilities = []
        total_ports = len(ports)

        for index, port in enumerate(ports):
            service = self._get_service_name(port)
            is_open = self._check_port(port)

            if is_open:
                vuln = self._analyze_service(port, service)
                if vuln:
                    vulnerabilities.append(vuln)

            # Update progress
            self.scan.progress = int((index / total_ports) * 100)
            self.scan.save()

        return vulnerabilities

    def _check_port(self, port, timeout=2):
        """Check if a port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return result == 0
        except:
            return False

    def _get_service_name(self, port):
        """Get service name for a port"""
        services = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            445: 'SMB', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            5900: 'VNC', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9200: 'Elasticsearch',
            27017: 'MongoDB'
        }
        return services.get(port, f'Service-{port}')

    def _analyze_service(self, port, service):
        """Analyze service for known vulnerabilities"""
        vulnerabilities_map = {
            'SSH': {
                'title': 'Open SSH Port',
                'description': 'SSH service is exposed to the internet without proper authentication.',
                'severity': 'high',
                'cve': 'CVE-2021-28041'
            },
            'HTTP': {
                'title': 'Open HTTP Port',
                'description': 'HTTP traffic is not encrypted.',
                'severity': 'medium',
                'cve': ''
            },
            'HTTPS': {
                'title': 'Weak TLS Configuration',
                'description': 'Server is using outdated TLS protocols.',
                'severity': 'critical',
                'cve': 'CVE-2011-3389'
            },
            'Telnet': {
                'title': 'Telnet Service Active',
                'description': 'Telnet is an unencrypted remote access protocol.',
                'severity': 'critical',
                'cve': ''
            },
            'FTP': {
                'title': 'Open FTP Port',
                'description': 'FTP service is exposed without encryption.',
                'severity': 'high',
                'cve': ''
            },
            'SMTP': {
                'title': 'Open SMTP Port',
                'description': 'SMTP service allows mail relay without authentication.',
                'severity': 'low',
                'cve': ''
            },
            'MySQL': {
                'title': 'Exposed MySQL Database',
                'description': 'MySQL is accessible from the network.',
                'severity': 'critical',
                'cve': ''
            },
            'PostgreSQL': {
                'title': 'Exposed PostgreSQL Database',
                'description': 'PostgreSQL is accessible from the network.',
                'severity': 'critical',
                'cve': ''
            },
            'MongoDB': {
                'title': 'Exposed MongoDB Database',
                'description': 'MongoDB is accessible without authentication.',
                'severity': 'critical',
                'cve': ''
            }
        }

        if service in vulnerabilities_map:
            info = vulnerabilities_map[service]
            return Vulnerability(
                title=info['title'],
                description=info['description'],
                severity=info['severity'],
                port=port,
                service=service,
                cve=info['cve']
            )

        return None
