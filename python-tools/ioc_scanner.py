#!/usr/bin/env python3
import json
import sys
import hashlib
import os
import re
import requests
from pathlib import Path

class IOCScanner:
    def __init__(self):
        self.ioc_database = self.load_ioc_database()
    
    def load_ioc_database(self):
        """Load known IOCs from database or file"""
        # This would typically come from external feeds
        return {
            # Known malicious hashes (example)
            "d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4": "Example malware hash",
            "5d41402abc4b2a76b9719d911017c592": "Test malicious file",
            
            # Known suspicious process names
            "lsass_dump.exe": "Credential dumping tool",
            "mimikatz.exe": "Credential dumping tool",
            "procdump.exe": "Legitimate tool often abused",
            "powershell_encoded": "Encoded PowerShell command",
            
            # Network indicators
            "evil-domain.com": "Known malicious domain",
            "192.168.1.100": "Suspicious internal IP"
        }
    
    def scan_file(self, file_path):
        """Comprehensive IOC scan of a file"""
        try:
            if not os.path.exists(file_path):
                return {"error": f"File not found: {file_path}"}
            
            # Calculate file hashes
            hashes = self.calculate_hashes(file_path)
            
            # Check against known IOCs
            ioc_matches = self.check_hashes(hashes)
            
            # Additional checks
            file_size = os.path.getsize(file_path)
            filename = os.path.basename(file_path)
            
            # Check filename against known malicious names
            filename_matches = self.check_filename(filename)
            ioc_matches.extend(filename_matches)
            
            return {
                "hashes": hashes,
                "ioc_matches": ioc_matches,
                "file_size": file_size,
                "filename": filename,
                "scan_time": os.path.getctime(file_path)
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def calculate_hashes(self, file_path):
        """Calculate multiple hash types for a file"""
        hashes = {
            "md5": "",
            "sha1": "",
            "sha256": "",
            "sha512": ""
        }
        
        try:
            with open(file_path, 'rb') as f:
                file_content = f.read()
                
                hashes["md5"] = hashlib.md5(file_content).hexdigest()
                hashes["sha1"] = hashlib.sha1(file_content).hexdigest()
                hashes["sha256"] = hashlib.sha256(file_content).hexdigest()
                hashes["sha512"] = hashlib.sha512(file_content).hexdigest()
                
        except Exception as e:
            print(f"Error calculating hashes: {e}")
        
        return hashes
    
    def check_hashes(self, hashes):
        """Check hashes against known IOCs"""
        matches = []
        
        for hash_type, hash_value in hashes.items():
            if hash_value in self.ioc_database:
                matches.append({
                    "type": "hash",
                    "value": hash_value,
                    "hash_type": hash_type,
                    "source": "Internal IOC Database",
                    "severity": "high",
                    "description": self.ioc_database[hash_value]
                })
        
        return matches
    
    def check_filename(self, filename):
        """Check filename against known malicious patterns"""
        matches = []
        filename_lower = filename.lower()
        
        # Check for known malicious patterns
        malicious_patterns = {
            "lsass": "LSASS memory access",
            "mimikatz": "Credential dumping tool",
            "procdump": "Process dumping tool",
            "powershell": "PowerShell execution",
            "encoded": "Encoded command",
            "script": "Suspicious script",
            "temp": "Temporary file execution"
        }
        
        for pattern, description in malicious_patterns.items():
            if pattern in filename_lower:
                matches.append({
                    "type": "filename",
                    "value": filename,
                    "source": "Filename pattern detection",
                    "severity": "medium",
                    "description": f"Filename contains '{pattern}': {description}"
                })
        
        return matches
    
    def check_virustotal(self, hash_value):
        """Check hash against VirusTotal (optional)"""
        # This would require API key and proper error handling
        # For MVP, we'll skip actual API calls to avoid dependencies
        return []

def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Please provide a file path"}))
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    # Initialize scanner
    scanner = IOCScanner()
    
    # Perform scan
    results = scanner.scan_file(file_path)
    print(json.dumps(results))

if __name__ == '__main__':
    main()