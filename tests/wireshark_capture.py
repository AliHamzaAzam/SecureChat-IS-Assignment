#!/usr/bin/env python3
"""
SecureChat Network Capture & Analysis Helper Script

This script helps capture and analyze SecureChat network traffic.
It can:
1. Start/stop tcpdump packet capture
2. Run the server/client
3. Generate Wireshark analysis reports

Usage:
    python tests/wireshark_capture.py --help
"""

import sys
import subprocess
import os
import time
import json
import argparse
from pathlib import Path
from datetime import datetime

SCRIPT_DIR = Path(__file__).parent
PROJECT_DIR = SCRIPT_DIR.parent
EVIDENCE_DIR = SCRIPT_DIR / "evidence"
PCAP_FILE = EVIDENCE_DIR / "secure_chat.pcap"
CAPTURE_PORT = 5000

# Ensure evidence directory exists
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


def log_info(msg: str):
    """Print info message."""
    print(f"[INFO] {msg}")


def log_success(msg: str):
    """Print success message."""
    print(f"[✓] {msg}")


def log_error(msg: str):
    """Print error message."""
    print(f"[✗] {msg}", file=sys.stderr)


def log_command(cmd: str):
    """Print command to run."""
    print(f"\n[COMMAND]\n$ {cmd}\n")


def start_capture() -> subprocess.Popen:
    """Start tcpdump packet capture."""
    log_info(f"Starting tcpdump capture on port {CAPTURE_PORT}...")
    
    # Remove old capture file
    if PCAP_FILE.exists():
        PCAP_FILE.unlink()
        log_info("Removed old PCAP file")
    
    cmd = [
        "sudo",
        "tcpdump",
        "-i", "lo",
        "-w", str(PCAP_FILE),
        "-q",
        f"port {CAPTURE_PORT}"
    ]
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(1)  # Give tcpdump time to start
        log_success(f"tcpdump started (PID: {process.pid})")
        log_info(f"Capturing to: {PCAP_FILE}")
        return process
    except Exception as e:
        log_error(f"Failed to start tcpdump: {e}")
        log_error("Note: tcpdump requires sudo privilege")
        return None


def stop_capture(process: subprocess.Popen):
    """Stop tcpdump packet capture."""
    if not process:
        return
    
    log_info("Stopping tcpdump capture...")
    process.terminate()
    
    try:
        process.wait(timeout=5)
        log_success("tcpdump stopped")
    except subprocess.TimeoutExpired:
        process.kill()
        log_success("tcpdump killed")
    
    # Check if PCAP file was created
    if PCAP_FILE.exists():
        size = PCAP_FILE.stat().st_size
        log_success(f"PCAP file created: {PCAP_FILE} ({size} bytes)")
    else:
        log_error("PCAP file not created")


def show_instructions():
    """Show user instructions for testing."""
    instructions = """
╔════════════════════════════════════════════════════════════════╗
║          SECURECHAT NETWORK CAPTURE INSTRUCTIONS               ║
╚════════════════════════════════════════════════════════════════╝

The packet capture is now running in the background.

Follow these steps in the client terminal:

1. Wait for server to start (you should see connection established)

2. REGISTER a new user:

3. LOGIN with the same credentials:

4. Send encrypted chat messages:
   > Hello, this is a secret message
   > Another encrypted message
   > Testing end-to-end encryption

5. Exchange messages a few times

6. Type "logout" to disconnect

7. The client will exit

Once done, packet capture will be stopped automatically.

All network traffic has been captured to:
  {pcap_file}

Next, open the PCAP file in Wireshark:
  wireshark {pcap_file}

Then analyze using the filters documented in:
  tests/WIRESHARK_ANALYSIS.md
""".format(pcap_file=PCAP_FILE)
    
    print(instructions)


def start_server() -> subprocess.Popen:
    """Start SecureChat server in subprocess."""
    log_info("Starting SecureChat server...")
    
    cmd = [
        sys.executable,
        "-m", "app.server.server"
    ]
    
    try:
        process = subprocess.Popen(
            cmd,
            cwd=str(PROJECT_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        log_success(f"Server started (PID: {process.pid})")
        time.sleep(2)  # Give server time to bind to port
        return process
    except Exception as e:
        log_error(f"Failed to start server: {e}")
        return None


def start_client() -> subprocess.Popen:
    """Start SecureChat client in subprocess."""
    log_info("Starting SecureChat client...")
    
    cmd = [
        sys.executable,
        "-m", "app.client.client"
    ]
    
    try:
        process = subprocess.Popen(
            cmd,
            cwd=str(PROJECT_DIR),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        log_success(f"Client started (PID: {process.pid})")
        return process
    except Exception as e:
        log_error(f"Failed to start client: {e}")
        return None


def stop_server(process: subprocess.Popen):
    """Stop server process."""
    if not process:
        return
    
    log_info("Stopping server...")
    process.terminate()
    
    try:
        process.wait(timeout=5)
        log_success("Server stopped")
    except subprocess.TimeoutExpired:
        process.kill()
        log_success("Server killed")


def generate_wireshark_report() -> None:
    """Generate Wireshark analysis report from PCAP."""
    if not PCAP_FILE.exists():
        log_error("PCAP file not found")
        return
    
    log_info("Generating Wireshark analysis report...")
    
    try:
        # Try to use tshark (command-line Wireshark)
        cmd = [
            "tshark",
            "-r", str(PCAP_FILE),
            "-T", "text",
            "-V"  # Verbose (all packet details)
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            # Save to text file
            report_file = EVIDENCE_DIR / "secure_chat_analysis.txt"
            with open(report_file, 'w') as f:
                f.write("SECURECHAT NETWORK ANALYSIS REPORT\n")
                f.write("=" * 70 + "\n")
                f.write(f"Generated: {datetime.now().isoformat()}\n")
                f.write(f"PCAP File: {PCAP_FILE}\n")
                f.write("=" * 70 + "\n\n")
                f.write(result.stdout)
            
            log_success(f"Report saved to: {report_file}")
        else:
            log_error(f"tshark error: {result.stderr}")
    
    except FileNotFoundError:
        log_error("tshark not found. Install with: brew install wireshark")
    except Exception as e:
        log_error(f"Failed to generate report: {e}")


def show_pcap_summary() -> None:
    """Show summary of captured packets."""
    if not PCAP_FILE.exists():
        log_error("PCAP file not found")
        return
    
    log_info("PCAP file summary:")
    
    try:
        # Use tcpdump to read summary
        cmd = [
            "tcpdump",
            "-r", str(PCAP_FILE),
            "-n"
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            # Show first 20 packets
            for line in lines[:20]:
                if line.strip():
                    print(f"  {line}")
            
            if len(lines) > 20:
                print(f"  ... ({len(lines) - 20} more packets)")
        else:
            log_error(f"tcpdump error: {result.stderr}")
    
    except Exception as e:
        log_error(f"Failed to show summary: {e}")


def create_json_manifest() -> None:
    """Create JSON manifest of captured data."""
    manifest = {
        "timestamp": datetime.now().isoformat(),
        "pcap_file": str(PCAP_FILE),
        "pcap_exists": PCAP_FILE.exists(),
        "pcap_size_bytes": PCAP_FILE.stat().st_size if PCAP_FILE.exists() else 0,
        "capture_port": CAPTURE_PORT,
        "evidence_directory": str(EVIDENCE_DIR),
        "analysis_guide": "tests/WIRESHARK_ANALYSIS.md"
    }
    
    manifest_file = EVIDENCE_DIR / "capture_manifest.json"
    with open(manifest_file, 'w') as f:
        json.dump(manifest, f, indent=2)
    
    log_success(f"Manifest saved to: {manifest_file}")


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="SecureChat Network Capture & Analysis Helper"
    )
    parser.add_argument(
        "--mode",
        choices=["capture", "analyze", "full"],
        default="full",
        help="Mode: capture (start packet capture only), analyze (analyze PCAP), full (both)"
    )
    parser.add_argument(
        "--no-server",
        action="store_true",
        help="Don't start server (use existing)"
    )
    
    args = parser.parse_args()
    
    print("\n" + "=" * 70)
    print("SECURECHAT NETWORK CAPTURE & ANALYSIS")
    print("=" * 70 + "\n")
    
    server_process = None
    capture_process = None
    
    try:
        # Start server unless --no-server flag
        if not args.no_server and args.mode in ["capture", "full"]:
            server_process = start_server()
            if not server_process:
                log_error("Failed to start server")
                return 1
        
        # Start packet capture
        if args.mode in ["capture", "full"]:
            capture_process = start_capture()
            if not capture_process:
                log_error("Failed to start packet capture")
                log_error("Note: Packet capture requires sudo")
                return 1
            
            # Show instructions
            show_instructions()
            
            # Wait for user to complete testing
            log_info("\nWaiting for testing to complete...")
            log_info("Press Ctrl+C when done\n")
            
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                log_info("\nStopping capture...")
        
        # Stop capture
        if capture_process:
            stop_capture(capture_process)
        
        # Generate analysis
        if args.mode in ["analyze", "full"]:
            log_info("\n" + "=" * 70)
            log_info("ANALYSIS")
            log_info("=" * 70)
            
            show_pcap_summary()
            generate_wireshark_report()
            create_json_manifest()
            
            log_info(f"\nTo open PCAP in Wireshark:")
            log_command(f"wireshark {PCAP_FILE}")
            
            log_info(f"\nFor analysis guide, see:")
            log_command(f"cat tests/WIRESHARK_ANALYSIS.md")
        
        log_success("\nCapture and analysis complete!")
        return 0
    
    except Exception as e:
        log_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    finally:
        # Cleanup
        if capture_process:
            stop_capture(capture_process)
        if server_process:
            stop_server(server_process)


if __name__ == "__main__":
    sys.exit(main())
