"""
Test script to check JSON serialization
"""

import sys
import json
from pathlib import Path

# Setup path
sys.path.insert(0, str(Path(__file__).parent))
from models.scan_model import Scan

def test_api_response():
    """Test what the API would return"""
    scan_id = "scan-1766317538.571765"
    
    print(f"Loading scan: {scan_id}")
    scan = Scan.get_by_id(scan_id)
    
    if not scan:
        print(f"❌ Scan {scan_id} not found")
        return
    
    # Build the response like the API does
    response = {
        'scanId': scan.id,
        'target': scan.target,
        'completedAt': scan.updated_at.isoformat(),
        'vulnerabilities': [v.to_dict() for v in scan.vulnerabilities],
        'stats': {
            'critical': sum(1 for v in scan.vulnerabilities if v.severity == 'critical'),
            'high': sum(1 for v in scan.vulnerabilities if v.severity == 'high'),
            'medium': sum(1 for v in scan.vulnerabilities if v.severity == 'medium'),
            'low': sum(1 for v in scan.vulnerabilities if v.severity == 'low')
        },
        'status': scan.status,
        'progress': scan.progress
    }
    
    print("\nAPI Response (as JSON):")
    print(json.dumps(response, indent=2))

if __name__ == '__main__':
    test_api_response()
