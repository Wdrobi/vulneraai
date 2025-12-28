"""
Test script to check scan details
"""

import sys
import json
from pathlib import Path

# Setup path
sys.path.insert(0, str(Path(__file__).parent))
from models.scan_model import Scan

def check_scan_details():
    """Check detailed scan information"""
    scan_id = "scan-1766317538.571765"  # The second most recent scan
    
    print(f"Loading scan: {scan_id}")
    scan = Scan.get_by_id(scan_id)
    
    if not scan:
        print(f"❌ Scan {scan_id} not found")
        return
    
    print(f"\n✓ Scan found!")
    print(f"  ID: {scan.id}")
    print(f"  Target: {scan.target}")
    print(f"  Status: {scan.status}")
    print(f"  Progress: {scan.progress}%")
    print(f"  Risk Score: {scan.risk_score}")
    print(f"  Risk Level: {scan.risk_level}")
    print(f"  Created At: {scan.created_at}")
    print(f"  Updated At: {scan.updated_at}")
    print(f"  Vulnerabilities Count: {len(scan.vulnerabilities)}")
    
    if scan.vulnerabilities:
        print(f"\n  First 3 Vulnerabilities:")
        for i, v in enumerate(scan.vulnerabilities[:3]):
            print(f"    {i+1}. {v.title}")
            print(f"       Severity: {v.severity}")
            print(f"       Port: {v.port}")
            print(f"       Service: {v.service}")
            print(f"       CVE: {v.cve}")
            print(f"       Remediation: {v.remediation[:50] if v.remediation else 'N/A'}...")
            print()

if __name__ == '__main__':
    check_scan_details()
