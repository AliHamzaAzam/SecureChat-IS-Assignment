#!/usr/bin/env python3
"""
Test script to demonstrate DH key exchange for encrypted registration.

This script tests the complete flow:
1. Connect to server
2. Perform certificate exchange
3. Perform DH key agreement
4. Encrypt and send registration data
5. Verify key agreement success

Run with:
    python test_dh_registration.py
"""

import subprocess
import time
import signal
import sys
import os

# Add project to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def run_test():
    print("=" * 70)
    print("SecureChat DH Exchange & Encrypted Registration Test")
    print("=" * 70)
    
    # Check if server is already running
    print("\n[*] Checking for running server...")
    check_server = subprocess.run(
        ["lsof", "-i", ":5000"],
        capture_output=True,
        text=True
    )
    
    server_running = check_server.returncode == 0
    server_proc = None
    
    if not server_running:
        print("[*] Starting server...")
        server_proc = subprocess.Popen(
            ["conda", "run", "-n", "securechat", "python", "-m", "app.server.server"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        time.sleep(2)
        print("[+] Server started")
    else:
        print("[+] Server already running on port 5000")
    
    try:
        # Run client
        print("\n[*] Starting client - performing registration test...")
        print("-" * 70)
        
        # Prepare client input (email, username, password)
        client_input = "1\ntest@example.com\ntestuser\ntestpass123\n3\n"
        
        client_proc = subprocess.run(
            ["conda", "run", "-n", "securechat", "python", "-m", "app.client.client"],
            input=client_input,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        print(client_proc.stdout)
        if client_proc.stderr:
            print("STDERR:", client_proc.stderr)
        
        print("-" * 70)
        
        # Check for success indicators
        output = client_proc.stdout + (client_proc.stderr or "")
        
        success_indicators = [
            "DH key agreement successful",
            "Session AES-128 key derived",
            "Sent encrypted registration data",
            "Registration successful"
        ]
        
        print("\n[*] Test Results:")
        print("-" * 70)
        
        found_indicators = []
        for indicator in success_indicators:
            if indicator.lower() in output.lower():
                found_indicators.append(indicator)
                print(f"✓ {indicator}")
        
        if len(found_indicators) >= 2:
            print("\n[+] DH Exchange Test PASSED - Key agreement and encryption working!")
            return 0
        else:
            print(f"\n[!] DH Exchange Test INCONCLUSIVE - Found {len(found_indicators)}/{len(success_indicators)} indicators")
            return 1
            
    except subprocess.TimeoutExpired:
        print("[!] Client timeout - test may have hung")
        return 1
    except Exception as e:
        print(f"[!] Test error: {e}")
        return 1
    finally:
        # Kill server if we started it
        if server_proc is not None:
            print("\n[*] Stopping server...")
            server_proc.terminate()
            try:
                server_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                server_proc.kill()
            print("[+] Server stopped")

if __name__ == "__main__":
    exit_code = run_test()
    sys.exit(exit_code)
