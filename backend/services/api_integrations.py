"""
VulneraAI - External API Integrations
Integrates Censys, NVD, and VirusTotal APIs for enhanced vulnerability detection
"""

import requests
import time
from typing import Dict, List, Optional
from config import Config

class APIIntegrations:
    """Handles integration with external security APIs"""
    
    def __init__(self):
        self.censys_id = Config.CENSYS_API_ID
        self.censys_secret = Config.CENSYS_API_SECRET
        self.nvd_key = Config.NVD_API_KEY
        self.virustotal_key = Config.VIRUSTOTAL_API_KEY
        
    # ==================== CENSYS API ====================
    
    def censys_search_host(self, ip_address: str) -> Optional[Dict]:
        """
        Search Censys for host information
        Returns: Host data including open ports, services, certificates, etc.
        """
        if not self.censys_id or not self.censys_secret:
            return None
            
        try:
            url = f"https://search.censys.io/api/v2/hosts/{ip_address}"
            response = requests.get(
                url,
                auth=(self.censys_id, self.censys_secret),
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            print(f"Censys API error: {str(e)}")
            return None
    
    def extract_censys_vulnerabilities(self, censys_data: Dict) -> List[Dict]:
        """Extract vulnerability information from Censys data"""
        vulnerabilities = []
        
        if not censys_data or 'result' not in censys_data:
            return vulnerabilities
        
        result = censys_data['result']
        
        # Extract service vulnerabilities
        if 'services' in result:
            for service in result['services']:
                port = service.get('port')
                service_name = service.get('service_name', 'Unknown')
                
                # Check for outdated software versions
                if 'software' in service:
                    for software in service['software']:
                        version = software.get('version', '')
                        product = software.get('product', '')
                        
                        if version and product:
                            vulnerabilities.append({
                                'source': 'Censys',
                                'title': f'Detected {product} {version} on port {port}',
                                'description': f'Service {service_name} running {product} version {version}',
                                'severity': 'medium',
                                'port': port,
                                'service': service_name,
                                'cve': ''
                            })
                
                # Check for weak TLS/SSL configurations
                if 'tls' in service:
                    tls_data = service['tls']
                    if 'certificates' in tls_data:
                        for cert in tls_data['certificates']:
                            if 'parsed' in cert:
                                parsed = cert['parsed']
                                if 'signature_algorithm' in parsed:
                                    sig_alg = parsed['signature_algorithm']['name']
                                    if 'sha1' in sig_alg.lower() or 'md5' in sig_alg.lower():
                                        vulnerabilities.append({
                                            'source': 'Censys',
                                            'title': 'Weak Certificate Signature Algorithm',
                                            'description': f'Certificate uses weak {sig_alg} algorithm',
                                            'severity': 'high',
                                            'port': port,
                                            'service': service_name,
                                            'cve': 'CVE-2020-1967'
                                        })
        
        return vulnerabilities
    
    # ==================== NVD API ====================
    
    def nvd_search_cve(self, cve_id: str) -> Optional[Dict]:
        """
        Search NVD for CVE details
        Returns: Detailed CVE information including CVSS scores, description, references
        """
        if not self.nvd_key:
            return None
            
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            headers = {'apiKey': self.nvd_key}
            params = {'cveId': cve_id}
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            print(f"NVD API error: {str(e)}")
            return None
    
    def nvd_search_by_keyword(self, keyword: str, results_per_page: int = 10) -> Optional[Dict]:
        """
        Search NVD by keyword (e.g., product name, vendor)
        Returns: List of relevant CVEs
        """
        if not self.nvd_key:
            return None
            
        try:
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            headers = {'apiKey': self.nvd_key}
            params = {
                'keywordSearch': keyword,
                'resultsPerPage': results_per_page
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=15)
            
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            print(f"NVD API error: {str(e)}")
            return None
    
    def enrich_with_nvd(self, service_name: str, version: str = None) -> List[Dict]:
        """
        Enrich vulnerability data with NVD CVE information
        """
        vulnerabilities = []
        
        # Search for CVEs related to the service
        search_term = f"{service_name}"
        if version:
            search_term += f" {version}"
        
        nvd_data = self.nvd_search_by_keyword(search_term, results_per_page=5)
        
        if nvd_data and 'vulnerabilities' in nvd_data:
            for item in nvd_data['vulnerabilities']:
                cve_data = item.get('cve', {})
                cve_id = cve_data.get('id', '')
                
                descriptions = cve_data.get('descriptions', [])
                description = descriptions[0].get('value', '') if descriptions else 'No description available'
                
                # Get CVSS score
                metrics = cve_data.get('metrics', {})
                cvss_score = 0
                severity = 'unknown'
                
                if 'cvssMetricV31' in metrics:
                    cvss_v3 = metrics['cvssMetricV31'][0]['cvssData']
                    cvss_score = cvss_v3.get('baseScore', 0)
                    severity = cvss_v3.get('baseSeverity', 'unknown').lower()
                elif 'cvssMetricV2' in metrics:
                    cvss_v2 = metrics['cvssMetricV2'][0]['cvssData']
                    cvss_score = cvss_v2.get('baseScore', 0)
                    if cvss_score >= 7.0:
                        severity = 'high'
                    elif cvss_score >= 4.0:
                        severity = 'medium'
                    else:
                        severity = 'low'
                
                vulnerabilities.append({
                    'source': 'NVD',
                    'title': f'{cve_id} - {service_name} Vulnerability',
                    'description': description[:200] + '...' if len(description) > 200 else description,
                    'severity': severity,
                    'cvss_score': cvss_score,
                    'cve': cve_id,
                    'service': service_name
                })
        
        # Rate limiting - NVD allows 50 requests per 30 seconds with API key
        time.sleep(0.6)
        
        return vulnerabilities
    
    # ==================== VirusTotal API ====================
    
    def virustotal_scan_ip(self, ip_address: str) -> Optional[Dict]:
        """
        Scan IP address using VirusTotal
        Returns: Malicious detection results, reputation score, etc.
        """
        if not self.virustotal_key:
            return None
            
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
            headers = {'x-apikey': self.virustotal_key}
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            print(f"VirusTotal API error: {str(e)}")
            return None
    
    def virustotal_scan_domain(self, domain: str) -> Optional[Dict]:
        """
        Scan domain using VirusTotal
        Returns: Malicious detection results, DNS records, subdomains, etc.
        """
        if not self.virustotal_key:
            return None
            
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {'x-apikey': self.virustotal_key}
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            print(f"VirusTotal API error: {str(e)}")
            return None
    
    def extract_virustotal_threats(self, vt_data: Dict, target: str) -> List[Dict]:
        """Extract threat information from VirusTotal data"""
        vulnerabilities = []
        
        if not vt_data or 'data' not in vt_data:
            return vulnerabilities
        
        data = vt_data['data']
        attributes = data.get('attributes', {})
        
        # Check malicious detections
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        malicious_count = last_analysis_stats.get('malicious', 0)
        suspicious_count = last_analysis_stats.get('suspicious', 0)
        
        if malicious_count > 0:
            vulnerabilities.append({
                'source': 'VirusTotal',
                'title': f'Malicious IP/Domain Detected',
                'description': f'{target} flagged as malicious by {malicious_count} security vendors',
                'severity': 'critical',
                'port': None,
                'service': 'Network',
                'cve': '',
                'detection_count': malicious_count
            })
        
        if suspicious_count > 0:
            vulnerabilities.append({
                'source': 'VirusTotal',
                'title': f'Suspicious Activity Detected',
                'description': f'{target} flagged as suspicious by {suspicious_count} security vendors',
                'severity': 'high',
                'port': None,
                'service': 'Network',
                'cve': '',
                'detection_count': suspicious_count
            })
        
        # Check reputation score
        reputation = attributes.get('reputation', 0)
        if reputation < -50:
            vulnerabilities.append({
                'source': 'VirusTotal',
                'title': 'Poor Reputation Score',
                'description': f'{target} has a poor reputation score of {reputation}',
                'severity': 'high',
                'port': None,
                'service': 'Network',
                'cve': ''
            })
        
        return vulnerabilities
