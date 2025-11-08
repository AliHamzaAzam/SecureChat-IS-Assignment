"""
SecureChat TCP client with basic protocol communication.

This module implements a basic TCP client that:
    1. Loads client certificate and private key from certs/
    2. Connects to a remote server
    3. Sends and receives JSON messages with length-prefixed framing
    4. Provides a menu-driven interface for user interactions

Message Framing:
    Each message is prefixed with a 4-byte big-endian length field:
    [4 bytes: message length] [JSON message data]
    
    Example:
        Message: {"type":"HELLO","nonce":"abc123"}
        Length: 37 bytes
        Wire format: 0x00 0x00 0x00 0x25 {"type":"HELLO","nonce":"abc123"}

Client Architecture:
    - Single-threaded for simplicity
    - Blocking socket operations
    - Length-prefixed protocol for reliable message boundaries
    - Error handling for network and protocol errors

Usage:
    python -m app.client.client

Environment Variables (.env):
    SERVER_HOST: Server hostname or IP (default: 127.0.0.1)
    SERVER_PORT: Server port (default: 5000)
"""

import socket
import struct
import sys
import os
import json
import logging
import secrets
import base64
from pathlib import Path
from dotenv import load_dotenv

# Handle imports whether run as module or script
try:
    from app.common.protocol import ControlPlaneMsg, MessageType, serialize_message, deserialize_message
    from app.crypto.cert_validator import load_certificate, load_certificate_from_pem_string, validate_certificate
except ModuleNotFoundError:
    # Add parent directory to path when run as script
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
CLIENT_CERT_PATH = CERT_DIR / "client_cert.pem"
CLIENT_KEY_PATH = CERT_DIR / "client_key.pem"
CA_CERT_PATH = CERT_DIR / "ca_cert.pem"

# Message framing constants
LENGTH_PREFIX_SIZE = 4  # 4 bytes for message length
MAX_MESSAGE_SIZE = 1024 * 1024  # 1 MB max message size


def load_client_credentials():
    """
    Load client certificate and private key from disk.

    Reads PEM-formatted certificate and private key files from the certs/ directory.
    These are used for authentication with the server.

    Returns:
        Tuple of (cert_pem: str, key_pem: str)
        - cert_pem: PEM-encoded X.509 certificate
        - key_pem: PEM-encoded RSA private key

    Raises:
        FileNotFoundError: If certificate or key files don't exist
        IOError: If files cannot be read

    Example:
        >>> cert, key = load_client_credentials()
        >>> "BEGIN CERTIFICATE" in cert
        True
    """
    try:
        if not CLIENT_CERT_PATH.exists():
            raise FileNotFoundError(f"Client certificate not found: {CLIENT_CERT_PATH}")
        if not CLIENT_KEY_PATH.exists():
            raise FileNotFoundError(f"Client private key not found: {CLIENT_KEY_PATH}")

        with open(CLIENT_CERT_PATH, "r") as f:
            cert_pem = f.read()

        with open(CLIENT_KEY_PATH, "r") as f:
            key_pem = f.read()

        logger.info("Client credentials loaded successfully")
        logger.debug(f"  Certificate: {CLIENT_CERT_PATH}")
        logger.debug(f"  Private key: {CLIENT_KEY_PATH}")

        return cert_pem, key_pem

    except FileNotFoundError as e:
        logger.error(f"Missing credential file: {e}")
        raise
    except IOError as e:
        logger.error(f"Error reading credentials: {e}")
        raise


def connect_to_server(host: str, port: int) -> socket.socket:
    """
    Create TCP connection to the server.

    Establishes a TCP socket connection to the specified server address.
    The socket is returned for use with send_message() and receive_message().

    Args:
        host: Server hostname or IP address
        port: Server port number

    Returns:
        socket.socket: Connected socket object

    Raises:
        socket.error: If connection fails
        ValueError: If host or port invalid

    Example:
        >>> sock = connect_to_server("127.0.0.1", 5000)
        >>> # sock is now connected to server
        >>> sock.close()
    """
    if not isinstance(host, str):
        raise ValueError(f"host must be string, got {type(host)}")

    if not isinstance(port, int) or port < 1 or port > 65535:
        raise ValueError(f"port must be integer in range [1, 65535], got {port}")

    try:
        # Create TCP socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        logger.info(f"Connecting to server: {host}:{port}")
        print(f"[*] Connecting to server: {host}:{port}")

        # Connect to server
        client_socket.connect((host, port))

        logger.info(f"Connected to server: {host}:{port}")
        print(f"[+] Connected to server")

        return client_socket

    except socket.timeout as e:
        logger.error(f"Connection timeout to {host}:{port}")
        raise socket.error(f"Connection timeout: {e}")

    except socket.error as e:
        logger.error(f"Connection failed to {host}:{port}: {e}")
        raise

    except Exception as e:
        logger.error(f"Unexpected error connecting to server: {e}")
        raise


def send_message(sock: socket.socket, message_dict: dict) -> None:
    """
    Send a message to the server with length-prefixed framing.

    Serializes the message dictionary to JSON, prepends a 4-byte big-endian
    length field, and sends over the socket.

    Message format:
        [4 bytes: length] [JSON data]

    Args:
        sock: Connected socket object
        message_dict: Message dictionary to send

    Raises:
        TypeError: If message_dict is not a dictionary
        socket.error: If send fails
        ValueError: If message too large

    Example:
        >>> msg = {"type": "HELLO", "nonce": "abc123"}
        >>> send_message(sock, msg)
    """
    if not isinstance(message_dict, dict):
        raise TypeError(f"message_dict must be dict, got {type(message_dict)}")

    try:
        # Serialize to JSON
        json_str = json.dumps(message_dict, separators=(",", ":"))
        json_bytes = json_str.encode("utf-8")

        # Check message size
        if len(json_bytes) > MAX_MESSAGE_SIZE:
            raise ValueError(f"Message too large: {len(json_bytes)} bytes (max {MAX_MESSAGE_SIZE})")

        # Create length prefix (4 bytes, big-endian)
        length_prefix = struct.pack(">I", len(json_bytes))

        # Send length prefix + message
        full_message = length_prefix + json_bytes
        sock.sendall(full_message)

        logger.debug(f"Sent message: {json_str[:100]}...")

    except socket.timeout:
        logger.error("Send timeout")
        raise socket.error("Send timeout")

    except socket.error as e:
        logger.error(f"Socket error during send: {e}")
        raise

    except Exception as e:
        logger.error(f"Unexpected error during send: {e}")
        raise


def receive_message(sock: socket.socket) -> dict:
    """
    Receive a message from the server with length-prefixed framing.

    Reads the 4-byte length prefix, then reads exactly that many bytes of JSON data.
    Deserializes the JSON to a dictionary.

    Args:
        sock: Connected socket object

    Returns:
        dict: Deserialized message dictionary

    Raises:
        socket.error: If receive fails or connection closed
        ValueError: If message format invalid or too large

    Example:
        >>> msg_dict = receive_message(sock)
        >>> msg_dict["type"]
        'HELLO'
    """
    try:
        # Read length prefix (4 bytes, big-endian)
        length_bytes = sock.recv(LENGTH_PREFIX_SIZE)

        if not length_bytes:
            logger.error("Connection closed by server (empty length prefix)")
            raise socket.error("Connection closed by server")

        if len(length_bytes) < LENGTH_PREFIX_SIZE:
            logger.error(f"Incomplete length prefix: {len(length_bytes)} bytes")
            raise ValueError("Incomplete length prefix")

        # Unpack length
        message_length = struct.unpack(">I", length_bytes)[0]

        # Validate message size
        if message_length > MAX_MESSAGE_SIZE:
            logger.error(f"Message too large: {message_length} bytes (max {MAX_MESSAGE_SIZE})")
            raise ValueError(f"Message too large: {message_length} bytes")

        if message_length == 0:
            logger.error("Empty message received")
            raise ValueError("Empty message received")

        # Read exact message length
        json_bytes = b""
        while len(json_bytes) < message_length:
            chunk = sock.recv(message_length - len(json_bytes))

            if not chunk:
                logger.error(f"Connection closed while reading message ({len(json_bytes)}/{message_length} bytes)")
                raise socket.error("Connection closed by server")

            json_bytes += chunk

        # Deserialize JSON
        json_str = json_bytes.decode("utf-8")
        message_dict = json.loads(json_str)

        logger.debug(f"Received message: {json_str[:100]}...")

        return message_dict

    except socket.timeout:
        logger.error("Receive timeout")
        raise socket.error("Receive timeout")

    except socket.error as e:
        logger.error(f"Socket error during receive: {e}")
        raise

    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON received: {e}")
        raise ValueError(f"Invalid JSON: {e}")

    except Exception as e:
        logger.error(f"Unexpected error during receive: {e}")
        raise


def exchange_certificates(sock: socket.socket, client_cert_pem: str) -> str:
    """
    Perform certificate exchange with server.

    Implements the client side of the certificate exchange protocol:
        1. Send HELLO with client certificate and nonce
        2. Receive SERVER_HELLO from server with server certificate
        3. Validate server certificate against CA
        4. Store server certificate for session

    Args:
        sock: Connected socket to server
        client_cert_pem: Client's PEM-encoded certificate

    Returns:
        str: Server's PEM-encoded certificate if successful

    Raises:
        socket.error: If socket operations fail
        ValueError: If certificate validation fails or protocol error
        Exception: For any other protocol-level errors
    """
    try:
        # Step 1: Send HELLO with client certificate and nonce
        logger.info("Sending HELLO with client certificate")
        client_nonce = base64.b64encode(secrets.token_bytes(16)).decode('utf-8')
        hello_msg = ControlPlaneMsg(
            type=MessageType.HELLO.value,
            nonce=client_nonce,
            client_cert=client_cert_pem
        )
        msg_json = serialize_message(hello_msg)
        msg_bytes = msg_json.encode('utf-8')

        # Send with length prefix
        msg_len = len(msg_bytes)
        sock.sendall(
            msg_len.to_bytes(4, byteorder='big') + msg_bytes
        )
        logger.debug(f"HELLO sent ({msg_len} bytes)")
        print("[+] Sent HELLO with certificate to server")

        # Step 2: Receive SERVER_HELLO from server
        logger.info("Waiting for SERVER_HELLO from server")
        length_bytes = sock.recv(4)
        if not length_bytes:
            logger.error("Server closed connection before sending SERVER_HELLO")
            raise socket.error("Server closed connection")

        msg_len = int.from_bytes(length_bytes, byteorder='big')
        if msg_len > 1024 * 1024:  # 1MB max
            logger.error(f"SERVER_HELLO message too large: {msg_len} bytes")
            raise ValueError(f"Message too large: {msg_len} bytes")

        msg_bytes = b''
        while len(msg_bytes) < msg_len:
            chunk = sock.recv(msg_len - len(msg_bytes))
            if not chunk:
                logger.error("Connection closed while reading SERVER_HELLO")
                raise socket.error("Connection closed by server")
            msg_bytes += chunk

        msg_json = msg_bytes.decode('utf-8')
        msg_dict = json.loads(msg_json)
        logger.debug(f"Received message type: {msg_dict.get('type')}")

        # Validate message type
        if msg_dict.get('type') != MessageType.SERVER_HELLO.value:
            logger.error(f"Expected SERVER_HELLO, got {msg_dict.get('type')}")
            raise ValueError(f"Unexpected message type: {msg_dict.get('type')}")

        # Step 3: Extract server certificate
        server_cert_pem = msg_dict.get('server_cert')
        if not server_cert_pem:
            logger.error("SERVER_HELLO missing server_cert field")
            raise ValueError("SERVER_HELLO missing server_cert")

        # Step 4: Validate server certificate against CA
        logger.info("Validating server certificate")
        try:
            server_cert_obj = load_certificate_from_pem_string(server_cert_pem)
        except Exception as e:
            logger.error(f"Failed to load server certificate: {e}")
            raise ValueError(f"Invalid server certificate: {e}")

        try:
            ca_cert = load_certificate(str(CA_CERT_PATH))
            is_valid, error_msg = validate_certificate(server_cert_obj, ca_cert)

            if not is_valid:
                logger.warning(f"Certificate validation failed: {error_msg}")
                print(f"[!] BAD_CERT: {error_msg}")
                raise ValueError(f"Server certificate validation failed: {error_msg}")

            logger.info("Server certificate validation successful")
            print("[+] Server certificate validated")

        except ValueError:
            raise
        except Exception as e:
            logger.error(f"Error during certificate validation: {e}")
            raise ValueError(f"Certificate validation error: {e}")

        # Step 5: Certificate exchange complete
        logger.info("Certificate exchange complete - session established")
        return server_cert_pem

    except socket.error as e:
        logger.error(f"Socket error during certificate exchange: {e}")
        raise

    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error: {e}")
        raise ValueError(f"Invalid JSON in certificate exchange: {e}")

    except Exception as e:
        logger.error(f"Error during certificate exchange: {e}")
        raise


def main_menu() -> int:
    """
    Display main menu and get user choice.

    Displays menu options and reads user input.

    Returns:
        int: User's menu choice (1, 2, or 3)

    Raises:
        EOFError: If EOF encountered (e.g., Ctrl+D)
    """
    print("\n" + "=" * 50)
    print("SecureChat Client")
    print("=" * 50)
    print("1. Register")
    print("2. Login")
    print("3. Exit")
    print("=" * 50)

    while True:
        try:
            choice = input("Select option (1-3): ").strip()

            if choice in ["1", "2", "3"]:
                return int(choice)
            else:
                print("Invalid choice. Please select 1, 2, or 3.")

        except EOFError:
            print("\nEOF received")
            return 3
        except KeyboardInterrupt:
            print("\nInterrupted by user")
            return 3
        except Exception as e:
            print(f"Error reading input: {e}")
            return 3


def main():
    """
    Main client entry point.

    Loads credentials, connects to server, performs certificate exchange,
    and presents user menu.

    Exit codes:
        0: Normal shutdown
        1: Fatal error
    """
    try:
        # Load client credentials
        cert_pem, key_pem = load_client_credentials()
        print("[+] Client credentials loaded")

        # Connect to server
        sock = connect_to_server(SERVER_HOST, SERVER_PORT)

        # Perform certificate exchange with server
        try:
            server_cert_pem = exchange_certificates(sock, cert_pem)
            print("[+] Certificate exchange successful")
        except (socket.error, ValueError) as e:
            logger.error(f"Certificate exchange failed: {e}")
            print(f"[!] Certificate exchange failed: {e}")
            sock.close()
            sys.exit(1)

        while True:
            choice = main_menu()

            if choice == 1:
                print("\n[*] Register option selected")
                print("    TODO: Implement registration protocol")
                # TODO: Implement registration
                # Example:
                # username = input("Enter username: ")
                # email = input("Enter email: ")
                # password = input("Enter password: ")
                # msg = ControlPlaneMsg(type="REGISTER", nonce="...", username=..., password=...)
                # send_message(sock, serialize_message(msg))
                # response = receive_message(sock)

            elif choice == 2:
                print("\n[*] Login option selected")
                print("    TODO: Implement login protocol")
                # TODO: Implement login
                # Example:
                # email = input("Enter email: ")
                # password = input("Enter password: ")
                # msg = ControlPlaneMsg(type="LOGIN", nonce="...", username=..., password=...)
                # send_message(sock, serialize_message(msg))
                # response = receive_message(sock)

            elif choice == 3:
                print("\n[*] Exiting client")
                break

        # Close connection
        sock.close()
        logger.info("Client closed connection")
        print("[*] Disconnected from server")

    except FileNotFoundError as e:
        logger.critical(f"Cannot start client: {e}")
        sys.exit(1)

    except socket.error as e:
        logger.critical(f"Connection error: {e}")
        sys.exit(1)

    except Exception as e:
        logger.critical(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
