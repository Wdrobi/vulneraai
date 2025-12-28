"""
Test script to check if scans are being saved to the database
"""

import sys
import sqlite3
from pathlib import Path

# Setup path
sys.path.insert(0, str(Path(__file__).parent))
from config import Config

def check_database():
    """Check the database for scans"""
    db_path = Config.DATABASE_PATH / Config.DATABASE_FILE
    
    print(f"Database path: {db_path}")
    print(f"Database exists: {db_path.exists()}")
    
    if not db_path.exists():
        print("❌ Database file does not exist yet")
        return
    
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Check tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print(f"\nTables in database: {[t['name'] for t in tables]}")
        
        # Check scans
        cursor.execute("SELECT COUNT(*) as count FROM scans")
        count = cursor.fetchone()
        print(f"\nTotal scans in database: {count['count']}")
        
        if count['count'] > 0:
            cursor.execute("SELECT id, target, status, progress, created_at FROM scans ORDER BY created_at DESC LIMIT 5")
            scans = cursor.fetchall()
            print("\nLast 5 scans:")
            for scan in scans:
                print(f"  ID: {scan['id']}")
                print(f"    Target: {scan['target']}")
                print(f"    Status: {scan['status']}")
                print(f"    Progress: {scan['progress']}%")
                print(f"    Created: {scan['created_at']}")
                print()
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Error accessing database: {str(e)}")

if __name__ == '__main__':
    check_database()
