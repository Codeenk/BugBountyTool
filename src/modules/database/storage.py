import sqlite3
from typing import List, Dict, Any
import json
import os
import datetime

class Storage:
    def __init__(self, db_path: str = "bug_bounty.db"):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize the database with required tables."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables if they don't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,
            target TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            results TEXT NOT NULL
        )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_scan(self, scan_type: str, target: str, results: Any) -> int:
        """
        Save scan results to database.
        
        Args:
            scan_type: Type of scan (e.g., 'port_scan', 'subdomain', 'fuzzing')
            target: Target of the scan
            results: Scan results (will be JSON serialized)
            
        Returns:
            ID of the saved scan
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        timestamp = datetime.datetime.now().isoformat()
        results_json = json.dumps(results)
        
        cursor.execute(
            'INSERT INTO scans (scan_type, target, timestamp, results) VALUES (?, ?, ?, ?)',
            (scan_type, target, timestamp, results_json)
        )
        
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return scan_id
    
    def get_scan(self, scan_id: int) -> Dict:
        """Get a specific scan by ID."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'id': row[0],
                'scan_type': row[1],
                'target': row[2],
                'timestamp': row[3],
                'results': json.loads(row[4])
            }
        return None
    
    def get_scans_by_target(self, target: str) -> List[Dict]:
        """Get all scans for a specific target."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM scans WHERE target = ? ORDER BY timestamp DESC', (target,))
        rows = cursor.fetchall()
        conn.close()
        
        return [{
            'id': row[0],
            'scan_type': row[1],
            'target': row[2],
            'timestamp': row[3],
            'results': json.loads(row[4])
        } for row in rows]
    
    def delete_scan(self, scan_id: int) -> bool:
        """Delete a scan by ID."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
        deleted = cursor.rowcount > 0
        
        conn.commit()
        conn.close()
        
        return deleted 