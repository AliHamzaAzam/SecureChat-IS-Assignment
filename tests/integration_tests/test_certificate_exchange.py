#!/usr/bin/env python3
"""
Test script to verify mutual certificate exchange between client and server.

This script:
1. Starts the server in a subprocess
2. Runs the client to perform certificate exchange
3. Captures and displays the results
"""

import subprocess
import time
import signal
import sys

def run_test():
    print("=" * 70)
    print("SecureChat Mutual Certificate Exchange Test")
    print("=" * 70)
    
    # Start server in background
    print("\n[*] Starting server...")
    server_proc = subprocess.Popen(
        ["conda", "run", "-n", "securechat", "python", "-m", "app.server.server"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        preexec_fn=lambda: signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    )
    
    # Wait for server to start
    time.sleep(2)
    
    print("[+] Server started with PID:", server_proc.pid)
    
    try:
        # Run client
        print("\n[*] Running client to perform certificate exchange...")
        print("-" * 70)
        
        client_proc = subprocess.Popen(
            ["conda", "run", "-n", "securechat", "python", "-m", "app.client.client"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        
        # Send exit command to client
        stdout, _ = client_proc.communicate(input="3\n", timeout=5)
        
        print(stdout)
        print("-" * 70)
        
        # Check if certificate exchange was successful
        if "Certificate exchange successful" in stdout:
            print("\n[+] ✓ Certificate exchange SUCCESSFUL")
            if "Server certificate validated" in stdout:
                print("[+] ✓ Server certificate validated")
            if "Client credentials loaded" in stdout:
                print("[+] ✓ Client credentials loaded")
            if "Connected to server" in stdout:
                print("[+] ✓ Client connected to server")
            return True
        else:
            print("\n[!] ✗ Certificate exchange FAILED")
            if "BAD_CERT" in stdout:
                print("[!] Certificate validation error")
            return False
            
    except subprocess.TimeoutExpired:
        print("[!] Client timeout")
        client_proc.kill()
        return False
    except Exception as e:
        print(f"[!] Error: {e}")
        return False
    finally:
        # Kill server
        print("\n[*] Stopping server...")
        server_proc.send_signal(signal.SIGINT)
        try:
            server_proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            server_proc.kill()
        print("[+] Server stopped")

if __name__ == "__main__":
    success = run_test()
    sys.exit(0 if success else 1)
