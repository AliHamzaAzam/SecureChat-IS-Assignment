"""
SecureChat TCP server with certificate-based authentication.

This module implements a basic TCP server that:
    1. Loads server certificate and private key from certs/
    2. Listens on a configurable port (default 5000)
    3. Accepts client connections
    4. Handles certificate exchange and protocol handshake
    5. Manages graceful shutdown on SIGINT (Ctrl+C)

Server Architecture:
    - Single-threaded for simplicity (can be extended with threading/asyncio)
    - Certificate validation for all clients
    - Logging of all connections with timestamps
    - Graceful error handling and resource cleanup

Usage:
    python -m app.server.server

    To stop the server: Press Ctrl+C

Environment Variables (.env):
    SERVER_PORT: Port to listen on (default: 5000)
    SERVER_HOST: Host to bind to (default: 127.0.0.1)
"""

import socket
import signal
import sys
import os
import logging
import json
import secrets
import base64
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# Handle imports whether run as module or script
try:
    from app.common.protocol import ControlPlaneMsg, MessageType, serialize_message, deserialize_message
    from app.crypto.cert_validator import load_certificate, load_certificate_from_pem_string, validate_certificate
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from app.common.protocol import ControlPlaneMsg, MessageType, serialize_message, deserialize_message
    from app.crypto.cert_validator import load_certificate, load_certificate_from_pem_string, validate_certificate


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Configuration
SERVER_HOST = os.getenv("SERVER_HOST", "127.0.0.1")
SERVER_PORT = int(os.getenv("SERVER_PORT", "5000"))
CERT_DIR = Path(__file__).parent.parent.parent / "certs"
SERVER_CERT_PATH = CERT_DIR / "server_cert.pem"
SERVER_KEY_PATH = CERT_DIR / "server_key.pem"

# Global flag for graceful shutdown
shutdown_flag = False


def load_server_credentials():
    """
    Load server certificate and private key from disk.

    Reads PEM-formatted certificate and private key files from the certs/ directory.
    These are used for authentication with clients.

    Returns:
        Tuple of (cert_pem: str, key_pem: str)
        - cert_pem: PEM-encoded X.509 certificate
        - key_pem: PEM-encoded RSA private key

    Raises:
        FileNotFoundError: If certificate or key files don't exist
        IOError: If files cannot be read

    Example:
        >>> cert, key = load_server_credentials()
        >>> "BEGIN CERTIFICATE" in cert
        True
    """
    try:
        if not SERVER_CERT_PATH.exists():
            raise FileNotFoundError(f"Server certificate not found: {SERVER_CERT_PATH}")
        if not SERVER_KEY_PATH.exists():
            raise FileNotFoundError(f"Server private key not found: {SERVER_KEY_PATH}")

        with open(SERVER_CERT_PATH, "r") as f:
            cert_pem = f.read()

        with open(SERVER_KEY_PATH, "r") as f:
            key_pem = f.read()

        logger.info("Server credentials loaded successfully")
        logger.debug(f"  Certificate: {SERVER_CERT_PATH}")
        logger.debug(f"  Private key: {SERVER_KEY_PATH}")

        return cert_pem, key_pem

    except FileNotFoundError as e:
        logger.error(f"Missing credential file: {e}")
        raise
    except IOError as e:
        logger.error(f"Error reading credentials: {e}")
        raise


def handle_client(client_socket: socket.socket, client_address: tuple, server_cert_pem: str):
    """
    Handle a single client connection with certificate validation.

    Processes the client connection lifecycle:
        1. Send SERVER_HELLO with certificate and nonce
        2. Receive and validate client HELLO with certificate
        3. Establish trusted session or reject on validation failure
        4. TODO: Continue with DH key exchange and messaging

    Args:
        client_socket: Connected socket for the client
        client_address: Tuple of (client_ip, client_port)
        server_cert_pem: Server's PEM-encoded certificate

    Raises:
        socket.error: If socket operations fail
        Exception: For any protocol-level errors
    """
    client_ip, client_port = client_address
    client_id = f"{client_ip}:{client_port}"
    client_cert_pem = None

    logger.info(f"Client connected: {client_id}")
    timestamp = datetime.now().isoformat()
    logger.debug(f"  Connection timestamp: {timestamp}")

    try:
        # Step 1: Send SERVER_HELLO with server certificate and nonce
        logger.info(f"[{client_id}] Sending SERVER_HELLO with certificate")
        server_nonce = base64.b64encode(secrets.token_bytes(16)).decode('utf-8')
        server_hello = ControlPlaneMsg(
            type=MessageType.SERVER_HELLO.value,
            nonce=server_nonce,
            server_cert=server_cert_pem
        )
        msg_json = serialize_message(server_hello)
        msg_bytes = msg_json.encode('utf-8')
        
        # Send with length prefix
        msg_len = len(msg_bytes)
        client_socket.sendall(
            msg_len.to_bytes(4, byteorder='big') + msg_bytes
        )
        logger.debug(f"[{client_id}] SERVER_HELLO sent ({msg_len} bytes)")

        # Step 2: Receive HELLO from client
        logger.info(f"[{client_id}] Waiting for HELLO from client")
        length_bytes = client_socket.recv(4)
        if not length_bytes:
            logger.warning(f"[{client_id}] Client closed connection before sending HELLO")
            return

        msg_len = int.from_bytes(length_bytes, byteorder='big')
        if msg_len > 1024 * 1024:  # 1MB max
            logger.error(f"[{client_id}] HELLO message too large: {msg_len} bytes")
            return

        msg_bytes = b''
        while len(msg_bytes) < msg_len:
            chunk = client_socket.recv(msg_len - len(msg_bytes))
            if not chunk:
                logger.error(f"[{client_id}] Connection closed while reading HELLO")
                return
            msg_bytes += chunk

        msg_json = msg_bytes.decode('utf-8')
        msg_dict = json.loads(msg_json)
        logger.debug(f"[{client_id}] Received message type: {msg_dict.get('type')}")

        # Validate message type
        if msg_dict.get('type') != MessageType.HELLO.value:
            logger.error(f"[{client_id}] Expected HELLO, got {msg_dict.get('type')}")
            return

        # Step 3: Extract and validate client certificate
        client_cert_pem = msg_dict.get('client_cert')
        if not client_cert_pem:
            logger.error(f"[{client_id}] HELLO missing client_cert field")
            error_msg = ControlPlaneMsg(
                type=MessageType.LOGIN.value,
                nonce="error",
                username="error"
            )
            error_json = serialize_message(error_msg)
            error_bytes = error_json.encode('utf-8')
            client_socket.sendall(
                len(error_bytes).to_bytes(4, byteorder='big') + error_bytes
            )
            return

        # Load certificate for validation
        try:
            client_cert_obj = load_certificate_from_pem_string(client_cert_pem)
        except Exception as e:
            logger.error(f"[{client_id}] Failed to load client certificate: {e}")
            return

        # Validate certificate against CA
        try:
            ca_cert_path = CERT_DIR / "ca_cert.pem"
            ca_cert = load_certificate(str(ca_cert_path))
            is_valid, error_msg = validate_certificate(client_cert_obj, ca_cert)

            if not is_valid:
                logger.warning(f"[{client_id}] Certificate validation failed: {error_msg}")
                print(f"[{client_id}] BAD_CERT: {error_msg}")
                
                # Send error response
                error_response = ControlPlaneMsg(
                    type=MessageType.LOGIN.value,
                    nonce="error",
                    username="error"
                )
                error_json = serialize_message(error_response)
                error_bytes = error_json.encode('utf-8')
                client_socket.sendall(
                    len(error_bytes).to_bytes(4, byteorder='big') + error_bytes
                )
                return

            logger.info(f"[{client_id}] Certificate validation successful")
            print(f"[{client_id}] ✓ Client certificate validated")

        except Exception as e:
            logger.error(f"[{client_id}] Error during certificate validation: {e}")
            return

        # Step 4: Certificate exchange complete - continue with protocol
        logger.info(f"[{client_id}] Certificate exchange complete - session established")
        # TODO: Implement DH key exchange
        # TODO: Implement message handling loop

    except socket.timeout:
        logger.warning(f"[{client_id}] Connection timeout")

    except socket.error as e:
        logger.error(f"[{client_id}] Socket error: {e}")

    except json.JSONDecodeError as e:
        logger.error(f"[{client_id}] JSON decode error: {e}")

    except Exception as e:
        logger.error(f"[{client_id}] Unexpected error: {e}")

    finally:
        try:
            client_socket.close()
            logger.info(f"[{client_id}] Connection closed")
        except Exception as e:
            logger.error(f"[{client_id}] Error closing socket: {e}")


def signal_handler(signum, frame):
    """
    Handle SIGINT (Ctrl+C) for graceful shutdown.

    Sets the global shutdown flag which causes the server's main loop
    to exit cleanly, allowing resources to be released properly.

    Args:
        signum: Signal number (signal.SIGINT for Ctrl+C)
        frame: Current stack frame
    """
    global shutdown_flag
    logger.info("Shutdown signal received (SIGINT)")
    shutdown_flag = True


def start_server():
    """
    Start the TCP server and accept client connections.

    Creates a TCP socket, binds to the configured address and port,
    and enters a loop accepting client connections. The loop continues
    until a shutdown signal (Ctrl+C) is received.

    The server:
        1. Loads server credentials (certificate and private key)
        2. Creates a TCP socket in passive mode (listening)
        3. Binds to host:port
        4. Sets up signal handler for Ctrl+C
        5. Enters infinite loop accepting connections
        6. Handles each client in a separate call to handle_client()
        7. Gracefully closes on shutdown signal

    Raises:
        OSError: If socket creation or binding fails
        KeyboardInterrupt: When Ctrl+C is pressed (handled gracefully)

    Example:
        >>> start_server()
        [2025-11-08 14:30:00] INFO: Server credentials loaded successfully
        [2025-11-08 14:30:00] INFO: Server listening on 127.0.0.1:5000
        [2025-11-08 14:30:05] INFO: Client connected: 192.168.1.100:54321
        ...
    """
    global shutdown_flag

    try:
        # Load server credentials
        cert_pem, key_pem = load_server_credentials()

        # Create TCP socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind to address and port
        server_socket.bind((SERVER_HOST, SERVER_PORT))

        # Listen for incoming connections (max 5 pending connections)
        server_socket.listen(5)

        logger.info(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")
        print(f"[*] SecureChat server started on {SERVER_HOST}:{SERVER_PORT}")
        print(f"[*] Press Ctrl+C to stop the server")

        # Register signal handler for graceful shutdown
        signal.signal(signal.SIGINT, signal_handler)

        # Main server loop
        shutdown_flag = False
        while not shutdown_flag:
            try:
                # Accept incoming client connection
                # Set a timeout to allow checking shutdown_flag periodically
                server_socket.settimeout(1.0)

                try:
                    client_socket, client_address = server_socket.accept()
                except socket.timeout:
                    # Timeout is normal, just loop to check shutdown_flag
                    continue

                # Handle the client connection
                handle_client(client_socket, client_address, cert_pem)

            except Exception as e:
                if not shutdown_flag:
                    logger.error(f"Error in server loop: {e}")

        # Graceful shutdown
        logger.info("Shutting down server...")
        server_socket.close()
        logger.info("Server stopped")
        print("[*] Server stopped")

    except FileNotFoundError as e:
        logger.critical(f"Cannot start server: {e}")
        sys.exit(1)

    except OSError as e:
        logger.critical(f"Socket error: {e}")
        sys.exit(1)

    except Exception as e:
        logger.critical(f"Unexpected error: {e}")
        sys.exit(1)


def main():
    """
    Main entry point for the server.

    Starts the SecureChat server and handles any fatal errors.

    Exit codes:
        0: Normal shutdown
        1: Fatal error (missing credentials, socket error, etc.)
    """
    try:
        start_server()
    except KeyboardInterrupt:
        logger.info("Server interrupted by user")
        print("\n[*] Server stopped by user")
    except Exception as e:
        logger.critical(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
