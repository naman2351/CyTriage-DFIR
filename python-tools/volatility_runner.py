#!/usr/bin/env python3
import json
import sys
import os
import subprocess
import re

def determine_profile(memory_dump):
    """Try to automatically determine the correct profile"""
    try:
        # Try windows.info first
        cmd = ['python3', 'volatility3/vol.py', '-f', memory_dump, 'windows.info']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        if result.returncode == 0:
            # Look for profile information in the output
            lines = result.stdout.split('\n')
            for line in lines:
                if 'Suggested Profile(s)' in line:
                    profile = line.split('Suggested Profile(s)')[-1].strip()
                    if profile:
                        return profile.split()[0]  # Take the first suggested profile
            
        # If windows.info fails, try other methods
        print("Trying alternative methods to determine profile...")
        
        # Try windows.version
        cmd = ['python3', 'volatility3/vol.py', '-f', memory_dump, 'windows.version']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if 'Profile suggestion' in line:
                    profile = line.split('Profile suggestion')[-1].strip()
                    if profile:
                        return profile
        
        # As a last resort, try common profiles
        common_profiles = [
            'Win10x64_19041',
            'Win10x64_18362', 
            'Win8SP1x64',
            'Win7SP1x64',
            'Win2008R2SP1x64'
        ]
        
        for profile in common_profiles:
            print(f"Trying profile: {profile}")
            # Test if this profile works with a simple command
            cmd = ['python3', 'volatility3/vol.py', '-f', memory_dump, '--profile', profile, 'windows.pslist']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0 and "Unsatisfied requirement" not in result.stderr:
                print(f"Found working profile: {profile}")
                return profile
                
    except Exception as e:
        print(f"Error determining profile: {e}")
    
    return None

def run_volatility_with_profile(memory_dump, profile=None):
    """Run volatility with a specific profile"""
    try:
        if profile:
            # Use the specified profile
            cmd = ['python3', 'volatility3/vol.py', '-f', memory_dump, '--profile', profile, 'windows.pslist']
        else:
            # Try without profile first
            cmd = ['python3', 'volatility3/vol.py', '-f', memory_dump, 'windows.pslist']
        
        print(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        
        print(f"Return code: {result.returncode}")
        
        if result.stderr:
            print(f"Stderr: {result.stderr[:500]}")
        
        if result.returncode == 0:
            return parse_pslist_output(result.stdout)
        else:
            return {"error": f"Volatility failed: {result.stderr[:200]}", "processes": []}
            
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}", "processes": []}

def parse_pslist_output(output):
    """Parse windows.pslist output"""
    processes = []
    lines = output.split('\n')
    
    for line in lines:
        line = line.strip()
        if line and not line.startswith(('Volatility', '---', 'Offset')):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    pid = int(parts[0])
                    process_name = parts[1]
                    processes.append({
                        "process_name": process_name,
                        "pid": pid,
                        "suspicious": False,
                        "reason": "Found in process list"
                    })
                except (ValueError, IndexError):
                    continue
    
    # Mark some common suspicious processes
    suspicious_processes = ['lsass.exe', 'services.exe', 'spoolsv.exe', 'svchost.exe']
    for process in processes:
        if process['process_name'].lower() in suspicious_processes:
            process['suspicious'] = True
            process['reason'] = 'Common target for malware'
    
    suspicious_count = sum(1 for p in processes if p['suspicious'])
    
    return {
        "analysis_type": "pslist",
        "process_count": len(processes),
        "suspicious_count": suspicious_count,
        "processes": processes
    }

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Please provide a memory dump file path"}))
        sys.exit(1)
    
    memory_dump = sys.argv[1]
    
    if not os.path.exists(memory_dump):
        print(json.dumps({"error": f"File not found: {memory_dump}"}))
        sys.exit(1)
    
    print(f"Analyzing: {memory_dump}")
    
    # First try to determine the profile
    profile = determine_profile(memory_dump)
    
    if profile:
        print(f"Using profile: {profile}")
        results = run_volatility_with_profile(memory_dump, profile)
    else:
        print("Could not determine profile, trying without...")
        results = run_volatility_with_profile(memory_dump)
    
    print(json.dumps(results, indent=2))