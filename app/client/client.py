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
import hashlib
from pathlib import Path
from dotenv import load_dotenv

# Handle imports whether run as module or script
try:
    from app.common.protocol import ControlPlaneMsg, MessageType, serialize_message, deserialize_message, DHClientMsg, DHServerMsg
    from app.crypto.cert_validator import load_certificate, load_certificate_from_pem_string, validate_certificate
    from app.crypto.dh_exchange import generate_dh_keypair, compute_shared_secret, get_dh_params
    from app.crypto.aes_crypto import aes_encrypt, aes_decrypt
except ModuleNotFoundError:
    # Add parent directory to path when run as script
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from app.common.protocol import ControlPlaneMsg, MessageType, serialize_message, deserialize_message, DHClientMsg, DHServerMsg
    from app.crypto.cert_validator import load_certificate, load_certificate_from_pem_string, validate_certificate
    from app.crypto.dh_exchange import generate_dh_keypair, compute_shared_secret, get_dh_params
    from app.crypto.aes_crypto import aes_encrypt, aes_decrypt


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




def perform_dh_exchange(sock: socket.socket) -> bytes:
    """
    Perform Diffie-Hellman key agreement with server for session encryption.

    Implements the client side of DH key exchange:
        1. Generate client DH keypair (a, A)
        2. Send DH_CLIENT with g, p, and A
        3. Receive DH_SERVER with server's public key B
        4. Compute shared secret and derive AES-128 session key

    Args:
        sock: Connected socket to server

    Returns:
        bytes: 16-byte AES-128 session key

    Raises:
        socket.error: If socket operations fail
        ValueError: If protocol error or invalid DH parameters
        Exception: For any other errors
    """
    try:
        logger.info("Starting DH key exchange")
        print("\n[*] Initiating DH key agreement for session encryption...")

        # Step 1: Generate client DH keypair
        logger.debug("Generating client DH keypair")
        client_dh_private, client_dh_public = generate_dh_keypair()
        
        # Get standard DH parameters
        p, g = get_dh_params()
        
        logger.debug(f"Generated client DH public key with {client_dh_public.bit_length()} bits")
        print(f"[+] Client DH keypair generated")
        print(f"    Generator (g): {g}")
        print(f"    Prime (p): {hex(p)[:50]}...")
        print(f"    Public key (A): {hex(client_dh_public)[:50]}...")

        # Step 2: Create and send DH_CLIENT message
        logger.info("Sending DH_CLIENT message")
        dh_client_msg = DHClientMsg(
            type=MessageType.DH_CLIENT.value,
            g=g,
            p=hex(p),
            A=hex(client_dh_public)
        )
        msg_json = serialize_message(dh_client_msg)
        msg_bytes = msg_json.encode('utf-8')

        msg_len = len(msg_bytes)
        sock.sendall(
            msg_len.to_bytes(4, byteorder='big') + msg_bytes
        )
        logger.debug(f"DH_CLIENT sent ({msg_len} bytes)")
        print(f"[+] Sent DH_CLIENT to server")

        # Step 3: Receive DH_SERVER from server
        logger.info("Waiting for DH_SERVER message")
        length_bytes = sock.recv(4)
        if not length_bytes:
            logger.error("Server closed connection before sending DH_SERVER")
            raise socket.error("Server closed connection")

        msg_len = int.from_bytes(length_bytes, byteorder='big')
        if msg_len > 1024 * 1024:
            logger.error(f"DH_SERVER message too large: {msg_len} bytes")
            raise ValueError(f"Message too large: {msg_len} bytes")

        msg_bytes = b''
        while len(msg_bytes) < msg_len:
            chunk = sock.recv(msg_len - len(msg_bytes))
            if not chunk:
                logger.error("Connection closed while reading DH_SERVER")
                raise socket.error("Connection closed by server")
            msg_bytes += chunk

        msg_json = msg_bytes.decode('utf-8')
        msg_dict = json.loads(msg_json)
        logger.debug(f"Received message type: {msg_dict.get('type')}")

        # Validate message type
        if msg_dict.get('type') != MessageType.DH_SERVER.value:
            logger.error(f"Expected DH_SERVER, got {msg_dict.get('type')}")
            raise ValueError(f"Unexpected message type: {msg_dict.get('type')}")

        # Step 4: Extract server DH public key (B)
        try:
            server_dh_B_hex = msg_dict.get('B')
            if not server_dh_B_hex:
                logger.error("DH_SERVER missing B field")
                raise ValueError("DH_SERVER missing B field")
            
            server_dh_public = int(server_dh_B_hex, 16)
            logger.debug(f"Received server DH public key with {server_dh_public.bit_length()} bits")
            print(f"[+] Received DH_SERVER from server")
            print(f"    Server public key (B): {hex(server_dh_public)[:50]}...")
        except (ValueError, AttributeError) as e:
            logger.error(f"Failed to parse DH_SERVER: {e}")
            raise ValueError(f"Invalid DH_SERVER format: {e}")

        # Step 5: Compute shared secret and derive session key
        try:
            session_key = compute_shared_secret(client_dh_private, server_dh_public)
            logger.info("DH key agreement successful - session key derived")
            print(f"[+] DH key agreement successful!")
            print(f"[+] Session AES-128 key derived: {session_key.hex()[:32]}...")
            return session_key
        except Exception as e:
            logger.error(f"Failed to compute shared secret: {e}")
            raise ValueError(f"Key agreement failed: {e}")

    except socket.error as e:
        logger.error(f"Socket error during DH exchange: {e}")
        raise

    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error: {e}")
        raise ValueError(f"Invalid JSON in DH_SERVER: {e}")

    except Exception as e:
        logger.error(f"Error during DH key exchange: {e}")
        raise


def register_user(sock: socket.socket, session_key: bytes):
    """
    Perform user registration with encrypted credentials.

    Prompts user for email, username, and password, generates random salt,
    computes salted SHA-256 hash, and sends encrypted registration data.

    Args:
        sock: Connected socket to server
        session_key: 16-byte AES-128 session key from DH exchange

    Raises:
        socket.error: If socket operations fail
        ValueError: If encryption fails
        Exception: For any other errors
    """
    try:
        print("\n" + "=" * 50)
        print("Registration")
        print("=" * 50)

        email = input("Enter email: ").strip()
        if not email:
            print("[!] Email cannot be empty")
            return

        username = input("Enter username: ").strip()
        if not username:
            print("[!] Username cannot be empty")
            return

        password = input("Enter password: ").strip()
        if not password:
            print("[!] Password cannot be empty")
            return

        # Generate random 16-byte salt
        logger.debug("Generating random salt for password hashing")
        salt = secrets.token_bytes(16)
        salt_b64 = base64.b64encode(salt).decode('utf-8')
        
        # Compute password hash: SHA256(salt + password)
        hash_input = salt + password.encode('utf-8')
        pwd_hash = hashlib.sha256(hash_input).hexdigest()
        
        logger.info(f"Generated salt and computed password hash for user {username}")
        print(f"\n[*] Hashing password with salt...")
        print(f"[+] Salt (base64): {salt_b64[:20]}...")
        print(f"[+] Password hash: {pwd_hash[:32]}...")

        # Create registration data JSON with hashed password
        registration_data = {
            "email": email,
            "username": username,
            "pwd_hash": pwd_hash,
            "salt": salt_b64
        }
        
        logger.info(f"Encrypting registration data for user {username}")
        print(f"\n[*] Encrypting registration data...")

        # Encrypt registration JSON
        plaintext_json = json.dumps(registration_data)
        ciphertext = aes_encrypt(plaintext_json, session_key)
        
        # Encode ciphertext to base64 for JSON compatibility
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
        
        logger.debug(f"Registration data encrypted ({len(ciphertext)} bytes)")
        print(f"[+] Registration data encrypted: {len(ciphertext)} bytes")

        # Create encrypted registration message
        encrypted_msg = {
            "type": "REGISTER_ENCRYPTED",
            "ciphertext": ciphertext_b64
        }

        # Send encrypted registration data
        msg_json = json.dumps(encrypted_msg, separators=(",", ":"))
        msg_bytes = msg_json.encode('utf-8')

        msg_len = len(msg_bytes)
        sock.sendall(
            msg_len.to_bytes(4, byteorder='big') + msg_bytes
        )
        
        logger.info(f"Sent encrypted registration for user {username}")
        print(f"[+] Sent encrypted registration data to server")
        
        # Receive response from server
        logger.info("Waiting for registration response from server")
        length_bytes = sock.recv(4)
        if not length_bytes:
            logger.error("Server closed connection before sending registration response")
            print(f"[!] Server closed connection")
            return

        msg_len = int.from_bytes(length_bytes, byteorder='big')
        if msg_len > 1024 * 1024:
            logger.error(f"Response message too large: {msg_len} bytes")
            print(f"[!] Response message too large")
            return

        msg_bytes = b''
        while len(msg_bytes) < msg_len:
            chunk = sock.recv(msg_len - len(msg_bytes))
            if not chunk:
                logger.error("Connection closed while reading registration response")
                print(f"[!] Connection closed by server")
                return
            msg_bytes += chunk

        msg_json = msg_bytes.decode('utf-8')
        response = json.loads(msg_json)
        
        success = response.get('success', False)
        message = response.get('message', 'Unknown response')
        
        if success:
            logger.info(f"Registration successful for user {username}")
            print(f"[+] Registration successful!")
            print(f"[+] {message}")
        else:
            logger.warning(f"Registration failed for user {username}: {message}")
            print(f"[!] Registration failed: {message}")

    except EOFError:
        print("\n[*] Registration cancelled")
    except KeyboardInterrupt:
        print("\n[*] Registration cancelled")
    except Exception as e:
        logger.error(f"Error during registration: {e}")
        print(f"[!] Registration failed: {e}")


def perform_chat_dh_exchange(sock: socket.socket) -> bytes:
    """
    Perform DH key exchange for chat session (fresh keypair).

    After successful login, initiates a new DH exchange specifically for
    encrypting chat messages. Uses a fresh keypair separate from the
    login/registration encryption key.

    Args:
        sock: Connected socket to server

    Returns:
        bytes: 16-byte AES-128 chat session key

    Raises:
        socket.error: If socket operations fail
        ValueError: If key derivation fails
    """
    try:
        logger.info("Starting chat session DH key exchange")
        print("\n[*] Initiating chat session key exchange...")
        
        # Generate fresh DH keypair for chat session
        client_private, client_public = generate_dh_keypair()
        logger.debug("Generated fresh DH keypair for chat session")
        print("[+] Generated fresh DH keypair")
        
        # Send DH_CLIENT with client's public key
        dh_client_msg = {
            "type": "DH_CLIENT",
            "dh_public": hex(client_public)
        }
        
        msg_json = json.dumps(dh_client_msg)
        msg_bytes = msg_json.encode('utf-8')
        sock.sendall(
            len(msg_bytes).to_bytes(4, byteorder='big') + msg_bytes
        )
        
        logger.info("Sent DH_CLIENT for chat session")
        print("[+] Sent DH_CLIENT to server")
        
        # Receive DH_SERVER from server
        logger.info("Waiting for DH_SERVER from server (chat session)")
        length_bytes = sock.recv(4)
        if not length_bytes:
            logger.error("Server closed connection during chat DH exchange")
            raise socket.error("Server closed connection")
        
        msg_len = int.from_bytes(length_bytes, byteorder='big')
        if msg_len > 1024 * 1024:
            logger.error(f"DH_SERVER message too large: {msg_len}")
            raise ValueError(f"Message too large: {msg_len}")
        
        msg_bytes = b''
        while len(msg_bytes) < msg_len:
            chunk = sock.recv(msg_len - len(msg_bytes))
            if not chunk:
                logger.error("Connection closed while reading DH_SERVER")
                raise socket.error("Connection closed by server")
            msg_bytes += chunk
        
        msg_json = msg_bytes.decode('utf-8')
        dh_server_msg = json.loads(msg_json)
        
        if dh_server_msg.get('type') != 'DH_SERVER':
            logger.error(f"Expected DH_SERVER, got {dh_server_msg.get('type')}")
            raise ValueError(f"Unexpected message type: {dh_server_msg.get('type')}")
        
        server_dh_public = int(dh_server_msg['dh_public'], 16)
        logger.debug("Received DH_SERVER with server public key")
        print("[+] Received DH_SERVER from server")
        
        # Compute shared secret and derive chat session key
        chat_session_key = compute_shared_secret(client_private, server_dh_public)
        
        logger.info(f"Chat session key derived: {chat_session_key.hex()[:16]}...")
        print(f"[+] Chat session key derived: {chat_session_key.hex()[:16]}...")
        
        return chat_session_key
        
    except Exception as e:
        logger.error(f"Chat DH exchange failed: {e}")
        print(f"[!] Chat key exchange failed: {e}")
        raise


def login_user(sock: socket.socket, session_key: bytes):
    """
    Perform user login with encrypted credentials and dual-gate authentication.

    Prompts user for email and password, encrypts and sends login data to server
    over the established DH session. Server verifies both certificate and password.

    Args:
        sock: Connected socket to server
        session_key: 16-byte AES-128 session key from DH exchange

    Raises:
        socket.error: If socket operations fail
        ValueError: If encryption fails
        Exception: For any other errors
    """
    try:
        print("\n" + "=" * 50)
        print("Login")
        print("=" * 50)

        email = input("Enter email: ").strip()
        if not email:
            print("[!] Email cannot be empty")
            return

        password = input("Enter password: ").strip()
        if not password:
            print("[!] Password cannot be empty")
            return

        # Create login data JSON
        login_data = {
            "email": email,
            "password": password
        }
        
        logger.info(f"Encrypting login data for user {email}")
        print(f"\n[*] Encrypting login data...")

        # Encrypt login JSON
        plaintext_json = json.dumps(login_data)
        ciphertext = aes_encrypt(plaintext_json, session_key)
        
        # Encode ciphertext to base64 for JSON compatibility
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
        
        logger.debug(f"Login data encrypted ({len(ciphertext)} bytes)")
        print(f"[+] Login data encrypted: {len(ciphertext)} bytes")

        # Create encrypted login message
        encrypted_msg = {
            "type": "LOGIN_ENCRYPTED",
            "ciphertext": ciphertext_b64
        }

        # Send encrypted login data
        msg_json = json.dumps(encrypted_msg, separators=(",", ":"))
        msg_bytes = msg_json.encode('utf-8')

        msg_len = len(msg_bytes)
        sock.sendall(
            msg_len.to_bytes(4, byteorder='big') + msg_bytes
        )
        
        logger.info(f"Sent encrypted login for user {email}")
        print(f"[+] Sent encrypted login data to server")
        
        # Receive response from server
        logger.info("Waiting for login response from server")
        length_bytes = sock.recv(4)
        if not length_bytes:
            logger.error("Server closed connection before sending login response")
            print(f"[!] Server closed connection")
            return

        msg_len = int.from_bytes(length_bytes, byteorder='big')
        if msg_len > 1024 * 1024:
            logger.error(f"Response message too large: {msg_len} bytes")
            print(f"[!] Response message too large")
            return

        msg_bytes = b''
        while len(msg_bytes) < msg_len:
            chunk = sock.recv(msg_len - len(msg_bytes))
            if not chunk:
                logger.error("Connection closed while reading login response")
                print(f"[!] Connection closed by server")
                return
            msg_bytes += chunk

        msg_json = msg_bytes.decode('utf-8')
        response = json.loads(msg_json)
        
        success = response.get('success', False)
        username = response.get('username')
        message = response.get('message', 'Unknown response')
        
        if success:
            logger.info(f"Login successful for user {username}")
            print(f"\n[+] Login successful!")
            print(f"[+] {message}")
            print(f"[*] Authenticated session established")
            
            # Perform chat session DH key exchange
            try:
                chat_session_key = perform_chat_dh_exchange(sock)
                logger.info(f"Chat session established for {username}")
                print(f"\n[+] Secure chat session established with {username}")
                print(f"    Session key: {chat_session_key.hex()[:16]}...")
                print(f"    Ready for chat (sequence number: 0)")
                # TODO: Enter chat message loop
                return True
            except Exception as e:
                logger.error(f"Failed to establish chat session: {e}")
                print(f"[!] Failed to establish chat session: {e}")
                return False
        else:
            logger.warning(f"Login failed for user {email}: {message}")
            print(f"\n[!] Login failed: {message}")
            return False

    except EOFError:
        print("\n[*] Login cancelled")
        return False
    except KeyboardInterrupt:
        print("\n[*] Login cancelled")
        return False
    except Exception as e:
        logger.error(f"Error during login: {e}")
        print(f"[!] Login failed: {e}")
        return False


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
    conducts DH key agreement, and presents user menu for registration/login.

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

        # Perform DH key agreement for session encryption
        try:
            session_key = perform_dh_exchange(sock)
            print("[+] DH key agreement successful")
        except (socket.error, ValueError) as e:
            logger.error(f"DH key agreement failed: {e}")
            print(f"[!] DH key agreement failed: {e}")
            sock.close()
            sys.exit(1)

        # Main menu loop
        while True:
            choice = main_menu()

            if choice == 1:
                print("\n[*] Register option selected")
                register_user(sock, session_key)
                # TODO: Handle server response to registration

            elif choice == 2:
                print("\n[*] Login option selected")
                login_user(sock, session_key)
                # TODO: Handle server response to login

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
