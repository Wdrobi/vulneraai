"""
VulneraAI - Scan Model
"""

import json
import os
import sys
import sqlite3
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import Config

class Vulnerability:
    def __init__(self, title, description, severity, port, service, cve=''):
        self.id = f"vuln-{datetime.utcnow().timestamp()}"
        self.title = title
        self.description = description
        self.severity = severity
        self.port = port
        self.service = service
        self.cve = cve
        self.remediation = self.get_remediation()

    def get_remediation(self):
        """Get remediation advice based on vulnerability"""
        remediations = {
            'Open SSH Port': 'Restrict SSH access using a firewall or implement key-based authentication.',
            'Weak TLS Configuration': 'Upgrade to TLS 1.2 or higher and disable old protocols.',
            'Open HTTP Port': 'Use HTTPS instead of HTTP to encrypt data in transit.',
            'Open FTP Port': 'Replace FTP with SFTP for secure file transfers.',
            'Telnet Service Active': 'Disable Telnet and use SSH for remote access.',
            'Open SMTP Port': 'Configure SMTP authentication and restrict relay settings.'
        }
        return remediations.get(self.title, 'Review and update security policies.')

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'port': self.port,
            'service': self.service,
            'cve': self.cve,
            'remediation': self.remediation
        }

class Scan:
    def __init__(self, target, scan_type='standard', id=None, user_id=None):
        self.id = id or f"scan-{datetime.utcnow().timestamp()}"
        self.target = target
        self.scan_type = scan_type
        self.user_id = user_id
        self.status = 'pending'  # pending, scanning, completed, cancelled
        self.progress = 0
        self.vulnerabilities = []
        self.risk_score = 0
        self.risk_level = 'Unknown'
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        self.started_at = None
        self.completed_at = None

    def save(self):
        """Save scan to database"""
        os.makedirs(str(Config.DATABASE_PATH), exist_ok=True)
        
        conn = sqlite3.connect(str(Config.DATABASE_PATH / Config.DATABASE_FILE))
        cursor = conn.cursor()

        scan_data = {
            'id': self.id,
            'user_id': self.user_id,
            'target': self.target,
            'scan_type': self.scan_type,
            'status': self.status,
            'progress': self.progress,
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'vulnerabilities': json.dumps([v.to_dict() for v in self.vulnerabilities]),
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

        cursor.execute('''
            INSERT OR REPLACE INTO scans 
            (id, user_id, target, scan_type, status, progress, risk_score, risk_level, vulnerabilities, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', tuple(scan_data.values()))

        conn.commit()
        conn.close()

    @staticmethod
    def get_by_id(scan_id):
        """Get scan by ID"""
        try:
            conn = sqlite3.connect(str(Config.DATABASE_PATH / Config.DATABASE_FILE))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
            row = cursor.fetchone()
            conn.close()

            if not row:
                return None

            scan = Scan(row['target'], row['scan_type'], row['id'], row['user_id'])
            scan.status = row['status']
            scan.progress = row['progress']
            scan.risk_score = row['risk_score']
            scan.risk_level = row['risk_level']
            scan.created_at = datetime.fromisoformat(row['created_at'])
            scan.updated_at = datetime.fromisoformat(row['updated_at'])

            # Load vulnerabilities
            if row['vulnerabilities']:
                vulns = json.loads(row['vulnerabilities'])
                for v in vulns:
                    vuln = Vulnerability(v['title'], v['description'], v['severity'], v['port'], v['service'], v.get('cve', ''))
                    vuln.id = v['id']
                    vuln.remediation = v.get('remediation', vuln.get_remediation())
                    scan.vulnerabilities.append(vuln)

            return scan
        except Exception as e:
            print(f"Error getting scan: {str(e)}")
            return None

    @staticmethod
    def get_recent_scans(limit=20, user_id=None):
        """Get recent scans, optionally filtered by user"""
        try:
            conn = sqlite3.connect(str(Config.DATABASE_PATH / Config.DATABASE_FILE))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            if user_id:
                cursor.execute('''
                    SELECT * FROM scans 
                    WHERE status = 'completed' AND user_id = ?
                    ORDER BY created_at DESC 
                    LIMIT ?
                ''', (user_id, limit))
            else:
                cursor.execute('''
                    SELECT * FROM scans 
                    WHERE status = 'completed'
                    ORDER BY created_at DESC 
                    LIMIT ?
                ''', (limit,))

            rows = cursor.fetchall()
            conn.close()

            scans = []
            for row in rows:
                scan = Scan.get_by_id(row['id'])
                if scan:
                    scans.append(scan)

            return scans
        except Exception as e:
            print(f"Error getting recent scans: {str(e)}")
            return []

    @staticmethod
    def count_all(user_id=None):
        """Count total scans, optionally filtered by user"""
        try:
            conn = sqlite3.connect(str(Config.DATABASE_PATH / Config.DATABASE_FILE))
            cursor = conn.cursor()
            if user_id:
                cursor.execute('SELECT COUNT(*) FROM scans WHERE user_id = ?', (user_id,))
            else:
                cursor.execute('SELECT COUNT(*) FROM scans')
            count = cursor.fetchone()[0]
            conn.close()
            return count
        except:
            return 0

    @staticmethod
    def count_by_status(status):
        """Count scans by status"""
        try:
            conn = sqlite3.connect(str(Config.DATABASE_PATH / Config.DATABASE_FILE))
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM scans WHERE status = ?', (status,))
            count = cursor.fetchone()[0]
            conn.close()
            return count
        except:
            return 0

    @staticmethod
    def get_average_risk_score():
        """Get average risk score"""
        try:
            conn = sqlite3.connect(str(Config.DATABASE_PATH / Config.DATABASE_FILE))
            cursor = conn.cursor()
            cursor.execute('SELECT AVG(risk_score) FROM scans WHERE status = ?', ('completed',))
            avg = cursor.fetchone()[0]
            conn.close()
            return round(avg, 2) if avg else 0
        except:
            return 0

    @staticmethod
    def count_vulnerabilities_by_severity(severity):
        """Count vulnerabilities by severity"""
        try:
            conn = sqlite3.connect(str(Config.DATABASE_PATH / Config.DATABASE_FILE))
            cursor = conn.cursor()
            cursor.execute('SELECT vulnerabilities FROM scans WHERE status = ?', ('completed',))
            rows = cursor.fetchall()
            conn.close()

            count = 0
            for row in rows:
                if row[0]:
                    vulns = json.loads(row[0])
                    count += sum(1 for v in vulns if v['severity'] == severity)
            return count
        except:
            return 0

    def estimate_remaining_time(self):
        """Estimate remaining scan time in seconds"""
        duration_map = {
            'quick': 300,        # 5 minutes
            'standard': 900,     # 15 minutes
            'comprehensive': 1800  # 30 minutes
        }
        
        total_duration = duration_map.get(self.scan_type, 900)
        elapsed = (datetime.utcnow() - self.created_at).total_seconds()
        remaining = max(0, int(total_duration - elapsed))
        
        return remaining

def init_db():
    """Initialize database"""
    os.makedirs(str(Config.DATABASE_PATH), exist_ok=True)
    
    db_path = str(Config.DATABASE_PATH / Config.DATABASE_FILE)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT,
            last_login TEXT,
            is_active INTEGER DEFAULT 1
        )
    ''')

    # Create scans table with user_id
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            target TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            status TEXT NOT NULL,
            progress INTEGER,
            risk_score INTEGER,
            risk_level TEXT,
            vulnerabilities TEXT,
            created_at TEXT,
            updated_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    conn.commit()
    conn.close()
