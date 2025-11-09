#!/usr/bin/env python3
"""
SecureChat PCAP Analysis Tool

Analyzes manually captured PCAPNG files to verify SecureChat protocol messages,
encryption, signatures, and cryptographic operations.

This tool does NOT capture packets - use tcpdump manually:

    # Terminal 1: Start server
    python -m app.server.server

    # Terminal 2: Start tcpdump capture
    sudo tcpdump -i lo0 -w tests/evidence/secure_chat.pcapng port 9999

    # Terminal 3: Run client and perform chat session

    # Terminal 2: Stop tcpdump (Ctrl+C)

    # Analyze the captured PCAP file
    python tests/wireshark_capture.py analyze tests/evidence/secure_chat.pcapng

Usage:
    python tests/wireshark_capture.py analyze <pcap_file>
    python tests/wireshark_capture.py list
"""

import sys
import subprocess
import json
import argparse
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

SCRIPT_DIR = Path(__file__).parent
PROJECT_DIR = SCRIPT_DIR.parent
EVIDENCE_DIR = SCRIPT_DIR / "evidence"

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


def log_section(title: str):
    """Print section header."""
    print(f"\n{'='*70}")
    print(f"{title:^70}")
    print(f"{'='*70}\n")


def check_tshark_available() -> bool:
    """Check if tshark (Wireshark CLI) is available."""
    try:
        result = subprocess.run(
            ["tshark", "--version"],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def extract_json_payload(hex_data: str) -> Optional[Dict[str, Any]]:
    """
    Extract JSON payload from hex data.
    
    Tries to locate and parse JSON object within hex data.
    """
    try:
        # Convert hex to ASCII, filtering for printable chars
        ascii_data = ""
        for i in range(0, len(hex_data), 2):
            try:
                byte_val = int(hex_data[i:i+2], 16)
                if 32 <= byte_val <= 126:  # Printable ASCII
                    ascii_data += chr(byte_val)
                elif byte_val in (9, 10, 13):  # Tab, newline, CR
                    ascii_data += chr(byte_val)
            except ValueError:
                pass

        # Try to find JSON object
        json_match = re.search(r'\{.*\}', ascii_data, re.DOTALL)
        if json_match:
            return json.loads(json_match.group())
    except (json.JSONDecodeError, ValueError):
        pass
    
    return None


def analyze_pcap_file(pcap_path: Path) -> Dict[str, Any]:
    """
    Analyze PCAP file using tshark to extract SecureChat protocol messages.
    
    Returns structured analysis of all captured packets.
    """
    if not pcap_path.exists():
        log_error(f"PCAP file not found: {pcap_path}")
        return {}

    if not check_tshark_available():
        log_error("tshark not found. Install with: brew install wireshark")
        return {}

    log_info(f"Analyzing PCAP: {pcap_path}")
    log_info(f"File size: {pcap_path.stat().st_size} bytes")

    analysis = {
        "timestamp": datetime.now().isoformat(),
        "pcap_file": str(pcap_path),
        "file_size_bytes": pcap_path.stat().st_size,
        "packets": [],
        "protocol_summary": {},
        "security_findings": [],
        "errors": []
    }

    try:
        # Extract TCP payload data using tshark
        cmd = [
            "tshark",
            "-r", str(pcap_path),
            "-Y", "tcp.port==9999",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "tcp.payload",
            "-E", "separator=|"
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            analysis["errors"].append(f"tshark error: {result.stderr}")
            return analysis

        # Parse output
        packet_num = 0
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue

            parts = line.split("|")
            if len(parts) < 4:
                continue

            frame_num, src_port, dst_port, payload_hex = parts[0], parts[1], parts[2], parts[3]

            if not payload_hex:
                continue

            packet_num += 1

            # Try to extract JSON payload
            json_payload = extract_json_payload(payload_hex)

            packet_info = {
                "number": int(frame_num),
                "src_port": int(src_port) if src_port else None,
                "dst_port": int(dst_port) if dst_port else None,
                "payload_hex": payload_hex[:100],  # First 100 chars
                "json_payload": json_payload,
                "message_type": None,
                "has_encryption": False,
                "has_signature": False,
                "direction": "client→server" if int(dst_port) == 9999 else "server→client"
            }

            # Analyze message type and properties
            if json_payload:
                msg_type = json_payload.get("type")
                packet_info["message_type"] = msg_type

                # Track protocol summary
                if msg_type not in analysis["protocol_summary"]:
                    analysis["protocol_summary"][msg_type] = 0
                analysis["protocol_summary"][msg_type] += 1

                # Check for encryption and signatures (including nested in "data" field)
                if "ct" in json_payload:  # ciphertext
                    packet_info["has_encryption"] = True
                if "sig" in json_payload:  # signature
                    packet_info["has_signature"] = True
                
                # Also check nested data field (for receipts)
                if "data" in json_payload and isinstance(json_payload["data"], dict):
                    nested_data = json_payload["data"]
                    if "ct" in nested_data:
                        packet_info["has_encryption"] = True
                    if "sig" in nested_data:
                        packet_info["has_signature"] = True
                    # Receipt with signature implies encryption of the signature itself
                    if "sig" in nested_data and msg_type == "receipt":
                        packet_info["has_encryption"] = True

            analysis["packets"].append(packet_info)

        log_success(f"Extracted {packet_num} packets from PCAP")

    except subprocess.TimeoutExpired:
        analysis["errors"].append("tshark timeout")
    except Exception as e:
        analysis["errors"].append(f"Error parsing PCAP: {str(e)}")

    # Generate security findings
    generate_security_findings(analysis)

    return analysis


def generate_security_findings(analysis: Dict[str, Any]):
    """Analyze packets and generate security findings."""
    if not analysis["packets"]:
        analysis["security_findings"].append("⚠ No packets found in capture")
        return

    msg_packets = [p for p in analysis["packets"] if p.get("message_type") == "MSG"]
    dh_packets = [p for p in analysis["packets"] if "DH_" in (p.get("message_type") or "")]

    if msg_packets:
        # Check encryption
        encrypted = sum(1 for p in msg_packets if p.get("has_encryption"))
        if encrypted == len(msg_packets):
            analysis["security_findings"].append(
                f"✅ All {len(msg_packets)} MSG packets are encrypted (confidentiality verified)"
            )
        elif encrypted > 0:
            analysis["security_findings"].append(
                f"⚠ {encrypted}/{len(msg_packets)} MSG packets encrypted"
            )
        else:
            analysis["security_findings"].append(
                "❌ No encrypted messages found"
            )

        # Check signatures
        signed = sum(1 for p in msg_packets if p.get("has_signature"))
        if signed == len(msg_packets):
            analysis["security_findings"].append(
                f"✅ All {len(msg_packets)} MSG packets are signed (integrity verified)"
            )
        elif signed > 0:
            analysis["security_findings"].append(
                f"⚠ {signed}/{len(msg_packets)} MSG packets signed"
            )
        else:
            analysis["security_findings"].append(
                "❌ No signed messages found"
            )

    if dh_packets:
        analysis["security_findings"].append(
            f"✅ DH key exchange detected ({len(dh_packets)} packets)"
        )

    # Check protocol sequence
    proto_types = [p.get("message_type") for p in analysis["packets"]]
    if "HELLO" in proto_types and "SERVER_HELLO" in proto_types:
        analysis["security_findings"].append(
            "✅ Certificate exchange completed (HELLO/SERVER_HELLO)"
        )

    # Summary
    total = len(analysis["packets"])
    analysis["security_findings"].append(f"\nTotal packets captured: {total}")


def format_analysis_text(analysis: Dict[str, Any]) -> str:
    """Format analysis as human-readable text."""
    output = []
    output.append("SECURECHAT PCAP ANALYSIS REPORT")
    output.append("=" * 70)
    output.append(f"Timestamp: {analysis['timestamp']}")
    output.append(f"PCAP File: {analysis['pcap_file']}")
    output.append(f"File Size: {analysis['file_size_bytes']} bytes")
    output.append("")

    if analysis["errors"]:
        output.append("ERRORS")
        output.append("-" * 70)
        for error in analysis["errors"]:
            output.append(f"  • {error}")
        output.append("")

    if analysis["protocol_summary"]:
        output.append("PROTOCOL MESSAGE SUMMARY")
        output.append("-" * 70)
        for msg_type, count in sorted(analysis["protocol_summary"].items()):
            output.append(f"  {msg_type}: {count} packet(s)")
        output.append("")

    if analysis["packets"]:
        output.append("PACKET DETAILS")
        output.append("-" * 70)
        for pkt in analysis["packets"]:
            output.append(f"\nPacket {pkt['number']} (Frame {pkt['number']}):")
            output.append(f"  Direction: {pkt['direction']}")
            output.append(f"  Type: {pkt['message_type'] or 'UNKNOWN'}")
            output.append(f"  Encrypted: {'Yes' if pkt['has_encryption'] else 'No'}")
            output.append(f"  Signed: {'Yes' if pkt['has_signature'] else 'No'}")
            if pkt["json_payload"]:
                payload_str = json.dumps(pkt["json_payload"], indent=4)
                for line in payload_str.split("\n"):
                    output.append(f"    {line}")

    if analysis["security_findings"]:
        output.append("\n" + "=" * 70)
        output.append("SECURITY FINDINGS")
        output.append("=" * 70)
        for finding in analysis["security_findings"]:
            output.append(finding)

    return "\n".join(output)


def save_analysis(analysis: Dict[str, Any], basename: str = "capture_analysis"):
    """Save analysis to JSON and text files."""
    # Save JSON
    json_file = EVIDENCE_DIR / f"{basename}.json"
    with open(json_file, "w") as f:
        json.dump(analysis, f, indent=2)
    log_success(f"Analysis saved: {json_file}")

    # Save text report
    text_file = EVIDENCE_DIR / f"{basename}.txt"
    with open(text_file, "w") as f:
        f.write(format_analysis_text(analysis))
    log_success(f"Report saved: {text_file}")

    # Save manifest
    manifest_file = EVIDENCE_DIR / f"{basename}_manifest.json"
    manifest = {
        "timestamp": datetime.now().isoformat(),
        "pcap_file": analysis["pcap_file"],
        "analysis_files": {
            "json": str(json_file),
            "text": str(text_file),
            "manifest": str(manifest_file)
        },
        "summary": {
            "total_packets": len(analysis["packets"]),
            "protocol_types": analysis["protocol_summary"],
            "errors": analysis["errors"]
        }
    }
    with open(manifest_file, "w") as f:
        json.dump(manifest, f, indent=2)
    log_success(f"Manifest saved: {manifest_file}")


def list_pcap_files():
    """List available PCAP files in evidence directory."""
    log_section("Available PCAP Files")

    pcap_files = list(EVIDENCE_DIR.glob("*.pcapng")) + list(EVIDENCE_DIR.glob("*.pcap"))

    if not pcap_files:
        print("No PCAP files found in tests/evidence/")
        print("\nTo capture traffic manually:")
        print("  1. Terminal 1: python -m app.server.server")
        print("  2. Terminal 2: sudo tcpdump -i lo0 -w tests/evidence/secure_chat.pcapng port 9999")
        print("  3. Terminal 3: python -m app.client.client")
        print("  4. Run your chat session")
        print("  5. Terminal 2: Ctrl+C to stop capture")
        return

    for i, pcap_file in enumerate(pcap_files, 1):
        size_mb = pcap_file.stat().st_size / (1024 * 1024)
        print(f"{i}. {pcap_file.name} ({size_mb:.2f} MB)")
        print(f"   Path: {pcap_file}")


def main():
    parser = argparse.ArgumentParser(
        description="SecureChat PCAP Analysis Tool"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # analyze subcommand
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a PCAPNG file")
    analyze_parser.add_argument(
        "pcap_file",
        type=Path,
        help="Path to PCAPNG file (.pcapng or .pcap)"
    )
    analyze_parser.add_argument(
        "-o", "--output",
        type=str,
        default="capture_analysis",
        help="Output filename (without extension)"
    )

    # list subcommand
    subparsers.add_parser("list", help="List available PCAP files")

    args = parser.parse_args()

    if args.command == "analyze":
        log_section("SECURECHAT PCAP ANALYZER")
        
        if not check_tshark_available():
            log_error("tshark not available. Install Wireshark:")
            log_error("  macOS: brew install wireshark")
            log_error("  Linux: sudo apt-get install wireshark")
            sys.exit(1)

        analysis = analyze_pcap_file(args.pcap_file)
        
        if analysis["packets"] or not analysis["errors"]:
            print(format_analysis_text(analysis))
            save_analysis(analysis, args.output)
        else:
            log_error("Failed to analyze PCAP file")
            sys.exit(1)

    elif args.command == "list":
        list_pcap_files()

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
