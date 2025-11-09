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
import hashlib
import time
import threading
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# Handle imports whether run as module or script
try:
    from app.common.protocol import ControlPlaneMsg, MessageType, serialize_message, deserialize_message, DHClientMsg, DHServerMsg
    from app.crypto.cert_validator import load_certificate, load_certificate_from_pem_string, validate_certificate, load_private_key_from_pem_string
    from app.crypto.dh_exchange import generate_dh_keypair, compute_shared_secret, get_dh_params
    from app.crypto.aes_crypto import aes_decrypt, aes_encrypt
    from app.crypto.rsa_signer import verify_signature_with_pem, compute_sha256, sign_data
    from app.server.registration import register_user, verify_login
    from app.storage.db import get_connection
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from app.common.protocol import ControlPlaneMsg, MessageType, serialize_message, deserialize_message, DHClientMsg, DHServerMsg
    from app.crypto.cert_validator import load_certificate, load_certificate_from_pem_string, validate_certificate, load_private_key_from_pem_string
    from app.crypto.dh_exchange import generate_dh_keypair, compute_shared_secret, get_dh_params
    from app.crypto.aes_crypto import aes_decrypt, aes_encrypt
    from app.crypto.rsa_signer import verify_signature_with_pem, compute_sha256, sign_data
    from app.server.registration import register_user, verify_login
    from app.storage.db import get_connection


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
        with open(SERVER_CERT_PATH, "r") as f:
            cert_pem = f.read()
        with open(SERVER_KEY_PATH, "r") as f:
            key_pem = f.read()
        logger.debug("Server credentials loaded from disk")
        return cert_pem, key_pem
    except FileNotFoundError as e:
        logger.critical(f"Server credentials not found: {e}")
        raise


def receive_chat_messages(client_socket: socket.socket, client_id: str, username: str, 
                          chat_session_key: bytes, client_cert_pem: str):
    """
    Receive and process encrypted chat messages from client.

    Implements message reception loop with:
    - Sequence number replay protection
    - RSA-PSS signature verification
    - AES-128-CBC decryption
    - Message display

    Args:
        client_socket: Connected socket to client
        client_id: Client identifier for logging
        username: Authenticated username
        chat_session_key: 16-byte AES-128 chat session key
        client_cert_pem: PEM-encoded client certificate for signature verification

    Raises:
        socket.error: If socket operations fail
    """
    try:
        logger.info(f"[{client_id}] Entering message reception loop for {username}")
        print(f"[{client_id}] [*] Waiting for chat messages from {username}...")
        
        last_seqno = 0
        
        while True:
            try:
                # Receive message
                length_bytes = client_socket.recv(4)
                if not length_bytes:
                    logger.info(f"[{client_id}] Client closed connection")
                    print(f"[{client_id}] [*] Client disconnected")
                    break
                
                msg_len = int.from_bytes(length_bytes, byteorder='big')
                if msg_len > 10 * 1024 * 1024:  # 10MB max
                    logger.error(f"[{client_id}] Message too large: {msg_len}")
                    break
                
                msg_bytes = b''
                while len(msg_bytes) < msg_len:
                    chunk = client_socket.recv(msg_len - len(msg_bytes))
                    if not chunk:
                        logger.error(f"[{client_id}] Connection closed while reading message")
                        return
                    msg_bytes += chunk
                
                msg_json = msg_bytes.decode('utf-8')
                msg_dict = json.loads(msg_json)
                
                # Validate message type
                if msg_dict.get('type') != 'MSG':
                    logger.warning(f"[{client_id}] Expected MSG, got {msg_dict.get('type')}")
                    continue
                
                # Extract message fields
                seqno = msg_dict.get('seqno')
                ts = msg_dict.get('ts')
                ct_b64 = msg_dict.get('ct')
                sig_b64 = msg_dict.get('sig')
                
                if not all([seqno, ts, ct_b64, sig_b64]):
                    logger.error(f"[{client_id}] Incomplete message fields")
                    continue
                
                logger.debug(f"[{client_id}] Received message: seqno={seqno}, ts={ts}")
                
                # CHECK 1: Replay protection - seqno must be > last received
                if seqno <= last_seqno:
                    logger.warning(f"[{client_id}] Replay detected: seqno={seqno}, last={last_seqno}")
                    print(f"[{client_id}] [!] REPLAY attack detected (seqno={seqno})")
                    continue
                
                # Decode ciphertext and signature
                try:
                    ciphertext = base64.b64decode(ct_b64)
                    signature = base64.b64decode(sig_b64)
                except Exception as e:
                    logger.error(f"[{client_id}] Failed to decode base64: {e}")
                    continue
                
                # CHECK 2: Signature verification
                # Compute digest: SHA256(seqno || ts || ciphertext)
                digest_data = (
                    seqno.to_bytes(4, byteorder='big') +
                    ts.to_bytes(8, byteorder='big') +
                    ciphertext
                )
                digest = compute_sha256(digest_data)
                
                try:
                    # Verify signature using client's certificate public key
                    is_valid = verify_signature_with_pem(digest, signature, client_cert_pem)
                    if not is_valid:
                        logger.warning(f"[{client_id}] Signature verification failed")
                        print(f"[{client_id}] [!] SIG_FAIL - Signature invalid (seqno={seqno})")
                        continue
                except Exception as e:
                    logger.error(f"[{client_id}] Signature verification error: {e}")
                    print(f"[{client_id}] [!] SIG_FAIL - Verification error: {e}")
                    continue
                
                logger.debug(f"[{client_id}] Signature verified for seqno={seqno}")
                
                # Decrypt message
                try:
                    plaintext = aes_decrypt(ciphertext, chat_session_key)
                except Exception as e:
                    logger.error(f"[{client_id}] Decryption failed: {e}")
                    print(f"[{client_id}] [!] Decryption failed")
                    continue
                
                # Update sequence number tracker
                last_seqno = seqno
                
                # Display message
                logger.info(f"[{client_id}] [{username}]: {plaintext}")
                print(f"[{client_id}] [{username}]: {plaintext}")
                
            except socket.timeout:
                # Timeout is normal in non-blocking mode, just continue
                continue
            except json.JSONDecodeError as e:
                logger.error(f"[{client_id}] Failed to parse message JSON: {e}")
                continue
            except Exception as e:
                logger.error(f"[{client_id}] Error processing message: {e}")
                continue
    
    except KeyboardInterrupt:
        logger.info(f"[{client_id}] Message loop interrupted")
    except Exception as e:
        logger.error(f"[{client_id}] Message loop error: {e}")


def send_chat_message_loop(client_socket: socket.socket, client_id: str, username: str,
                          chat_session_key: bytes, server_key_pem: str, server_cert_pem: str):
    """
    Server console input loop: read messages, encrypt, sign, and send to client.

    Reads server console input, encrypts with chat session key, creates RSA-PSS signature,
    and sends ChatMsg with sequence number and timestamp for replay protection.

    Args:
        client_socket: Connected socket to client
        client_id: Client identifier for logging
        username: Authenticated client username for display
        chat_session_key: 16-byte AES-128 chat session key
        server_key_pem: PEM-encoded server private key for signing
        server_cert_pem: PEM-encoded server certificate (for display/logging)

    Raises:
        socket.error: If socket operations fail
        Exception: For any other errors
    """
    try:
        logger.info(f"[{client_id}] Server sending messages to {username}")
        print(f"[{client_id}] [*] Enter messages for {username} (type 'exit' to stop sending)")
        
        # Load private key for signing
        try:
            server_private_key = load_private_key_from_pem_string(server_key_pem)
        except Exception as e:
            logger.error(f"[{client_id}] Failed to load server private key: {e}")
            print(f"[{client_id}] [!] Error: Could not load server signing key: {e}")
            return
        
        seqno = 0
        
        while True:
            try:
                # Read message from server console
                message = input(f"[Server]: ").strip()
                
                if message.lower() == 'exit':
                    logger.info(f"[{client_id}] Server stopping message sending to {username}")
                    print(f"[{client_id}] [*] Stopping message sending")
                    break
                
                if not message:
                    continue
                
                # Encrypt message (aes_encrypt expects str, returns bytes)
                ciphertext = aes_encrypt(message, chat_session_key)
                ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
                
                # Increment sequence number
                seqno += 1
                
                # Get current timestamp (milliseconds)
                ts = int(time.time() * 1000)
                
                # Compute digest: SHA256(seqno || timestamp || ciphertext)
                digest_data = (
                    seqno.to_bytes(4, byteorder='big') +
                    ts.to_bytes(8, byteorder='big') +
                    ciphertext
                )
                digest = compute_sha256(digest_data)
                
                # Sign digest with server's private key
                signature = sign_data(digest, server_private_key)
                signature_b64 = base64.b64encode(signature).decode('utf-8')
                
                logger.debug(f"[{client_id}] Message encrypted and signed (seqno={seqno})")
                
                # Create ChatMsg
                chat_msg = {
                    "type": "MSG",
                    "seqno": seqno,
                    "ts": ts,
                    "ct": ciphertext_b64,
                    "sig": signature_b64
                }
                
                # Send to client
                msg_json = json.dumps(chat_msg)
                msg_bytes = msg_json.encode('utf-8')
                client_socket.sendall(
                    len(msg_bytes).to_bytes(4, byteorder='big') + msg_bytes
                )
                
                logger.info(f"[{client_id}] Server sent encrypted message (seqno={seqno}, ts={ts})")
                print(f"[{client_id}] [+] Server sent (seqno={seqno})")
                
            except KeyboardInterrupt:
                logger.info(f"[{client_id}] Server interrupted")
                print(f"\n[{client_id}] [*] Interrupted")
                break
            except EOFError:
                logger.info(f"[{client_id}] Server input closed")
                print(f"[{client_id}] [*] Input closed")
                break
            except socket.timeout:
                # Timeout is normal in non-blocking mode, just continue
                continue
            except socket.error as e:
                logger.error(f"[{client_id}] Network error sending message: {e}")
                print(f"[{client_id}] [!] Network error: {e}")
                break
            except Exception as e:
                logger.error(f"[{client_id}] Error sending message: {e}")
                print(f"[{client_id}] [!] Error: {e}")
    
    except Exception as e:
        logger.error(f"[{client_id}] Server message loop error: {e}")
        print(f"[{client_id}] [!] Server message loop error: {e}")


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


def handle_client(client_socket: socket.socket, client_address: tuple, server_cert_pem: str, server_key_pem: str):
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
        server_key_pem: Server's PEM-encoded private key for signing messages

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

        # Step 4: Certificate exchange complete - proceed with DH exchange
        logger.info(f"[{client_id}] Certificate exchange complete - initiating DH key agreement")
        print(f"[{client_id}] [*] Initiating DH key agreement for registration encryption...")

        # Step 5: Receive DH_CLIENT from client
        logger.info(f"[{client_id}] Waiting for DH_CLIENT message")
        length_bytes = client_socket.recv(4)
        if not length_bytes:
            logger.warning(f"[{client_id}] Client closed connection before sending DH_CLIENT")
            return

        msg_len = int.from_bytes(length_bytes, byteorder='big')
        if msg_len > 1024 * 1024:
            logger.error(f"[{client_id}] DH_CLIENT message too large: {msg_len} bytes")
            return

        msg_bytes = b''
        while len(msg_bytes) < msg_len:
            chunk = client_socket.recv(msg_len - len(msg_bytes))
            if not chunk:
                logger.error(f"[{client_id}] Connection closed while reading DH_CLIENT")
                return
            msg_bytes += chunk

        msg_json = msg_bytes.decode('utf-8')
        msg_dict = json.loads(msg_json)

        if msg_dict.get('type') != MessageType.DH_CLIENT.value:
            logger.error(f"[{client_id}] Expected DH_CLIENT, got {msg_dict.get('type')}")
            return

        # Extract client DH public key (A)
        try:
            client_dh_g = msg_dict.get('g')
            client_dh_p_hex = msg_dict.get('p')
            client_dh_A_hex = msg_dict.get('A')
            
            if not all([client_dh_A_hex, client_dh_p_hex, client_dh_g is not None]):
                logger.error(f"[{client_id}] DH_CLIENT missing required fields")
                return
            
            # Convert hex strings to integers
            client_dh_A = int(client_dh_A_hex, 16)
            client_dh_p = int(client_dh_p_hex, 16)
            
            logger.debug(f"[{client_id}] Received client DH public key (A) with {client_dh_A.bit_length()} bits")
        except (ValueError, AttributeError) as e:
            logger.error(f"[{client_id}] Failed to parse DH_CLIENT: {e}")
            return

        # Step 6: Generate server DH keypair
        try:
            server_dh_private, server_dh_public = generate_dh_keypair()
            logger.debug(f"[{client_id}] Generated server DH keypair")
        except Exception as e:
            logger.error(f"[{client_id}] Failed to generate server DH keypair: {e}")
            return

        # Step 7: Compute shared secret
        try:
            session_key = compute_shared_secret(server_dh_private, client_dh_A)
            logger.debug(f"[{client_id}] Computed shared secret - session key established")
            print(f"[{client_id}] [+] DH key agreement successful!")
            print(f"[{client_id}]     Server DH public key (B): {hex(server_dh_public)[:50]}...")
            print(f"[{client_id}]     Session AES-128 key derived: {session_key.hex()[:32]}...")
        except Exception as e:
            logger.error(f"[{client_id}] Failed to compute shared secret: {e}")
            return

        # Step 8: Send DH_SERVER with server public key (B)
        try:
            dh_server_msg = DHServerMsg(
                type=MessageType.DH_SERVER.value,
                B=hex(server_dh_public)
            )
            msg_json = serialize_message(dh_server_msg)
            msg_bytes = msg_json.encode('utf-8')
            
            msg_len = len(msg_bytes)
            client_socket.sendall(
                msg_len.to_bytes(4, byteorder='big') + msg_bytes
            )
            logger.debug(f"[{client_id}] DH_SERVER sent ({msg_len} bytes)")
            print(f"[{client_id}] [+] Sent DH_SERVER response to client")
        except Exception as e:
            logger.error(f"[{client_id}] Failed to send DH_SERVER: {e}")
            return

        logger.info(f"[{client_id}] DH key agreement complete - ready for encrypted registration/login")
        print(f"[{client_id}] [*] Waiting for encrypted registration/login data...")

        # Step 9: Receive encrypted registration/login message
        logger.info(f"[{client_id}] Waiting for encrypted auth message")
        length_bytes = client_socket.recv(4)
        if not length_bytes:
            logger.warning(f"[{client_id}] Client closed connection before sending encrypted message")
            return

        msg_len = int.from_bytes(length_bytes, byteorder='big')
        if msg_len > 1024 * 1024:
            logger.error(f"[{client_id}] Message too large: {msg_len} bytes")
            return

        msg_bytes = b''
        while len(msg_bytes) < msg_len:
            chunk = client_socket.recv(msg_len - len(msg_bytes))
            if not chunk:
                logger.error(f"[{client_id}] Connection closed while reading encrypted message")
                return
            msg_bytes += chunk

        msg_json = msg_bytes.decode('utf-8')
        msg_dict = json.loads(msg_json)
        msg_type = msg_dict.get('type')

        # Handle registration
        if msg_type == 'REGISTER_ENCRYPTED':
            logger.info(f"[{client_id}] Processing encrypted registration request")
            print(f"[{client_id}] [*] Processing registration request...")

            try:
                # Decrypt registration data
                ciphertext_b64 = msg_dict.get('ciphertext')
                if not ciphertext_b64:
                    logger.error(f"[{client_id}] REGISTER_ENCRYPTED missing ciphertext")
                    response = {
                        "type": "register_response",
                        "success": False,
                        "message": "Invalid registration message"
                    }
                    response_json = json.dumps(response, separators=(",", ":"))
                    response_bytes = response_json.encode('utf-8')
                    client_socket.sendall(
                        len(response_bytes).to_bytes(4, byteorder='big') + response_bytes
                    )
                    return

                ciphertext = base64.b64decode(ciphertext_b64)
                plaintext = aes_decrypt(ciphertext, session_key)
                registration_data = json.loads(plaintext)
                
                logger.debug(f"[{client_id}] Decrypted registration data successfully")
                print(f"[{client_id}] [+] Decrypted registration payload")

                # Extract fields
                email = registration_data.get('email', '').strip()
                username = registration_data.get('username', '').strip()
                pwd_hash = registration_data.get('pwd_hash', '').strip()
                salt_b64 = registration_data.get('salt', '').strip()

                if not all([email, username, pwd_hash, salt_b64]):
                    logger.error(f"[{client_id}] Registration data missing required fields")
                    response = {
                        "type": "register_response",
                        "success": False,
                        "message": "Missing required fields"
                    }
                    response_json = json.dumps(response, separators=(",", ":"))
                    response_bytes = response_json.encode('utf-8')
                    client_socket.sendall(
                        len(response_bytes).to_bytes(4, byteorder='big') + response_bytes
                    )
                    return

                logger.debug(f"[{client_id}] Extracted: email={email}, username={username}")

                # Decode salt from base64
                salt = base64.b64decode(salt_b64)

                # Get database connection
                try:
                    db_conn = get_connection()
                except Exception as e:
                    logger.error(f"[{client_id}] Failed to get database connection: {e}")
                    response = {
                        "type": "register_response",
                        "success": False,
                        "message": "Database connection failed"
                    }
                    response_json = json.dumps(response, separators=(",", ":"))
                    response_bytes = response_json.encode('utf-8')
                    client_socket.sendall(
                        len(response_bytes).to_bytes(4, byteorder='big') + response_bytes
                    )
                    return

                # Call register_user with password hash and salt
                # Note: register_user expects password, but we'll pass empty and use hash directly
                # For now, we'll create a custom registration call
                try:
                    cursor = db_conn.cursor()

                    # Check if email already exists
                    cursor.execute("SELECT email FROM users WHERE email = %s", (email,))
                    if cursor.fetchone():
                        cursor.close()
                        logger.warning(f"[{client_id}] Email already registered: {email}")
                        response = {
                            "type": "register_response",
                            "success": False,
                            "message": f"Email already registered: {email}"
                        }
                    else:
                        # Check if username already exists
                        cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
                        if cursor.fetchone():
                            cursor.close()
                            logger.warning(f"[{client_id}] Username already taken: {username}")
                            response = {
                                "type": "register_response",
                                "success": False,
                                "message": f"Username already taken: {username}"
                            }
                        else:
                            # Insert new user with provided hash and salt
                            cursor.execute(
                                "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
                                (email, username, salt, pwd_hash)
                            )
                            db_conn.commit()
                            cursor.close()
                            
                            logger.info(f"[{client_id}] User registered successfully: {username}")
                            print(f"[{client_id}] [+] User registered: {username}")
                            
                            response = {
                                "type": "register_response",
                                "success": True,
                                "message": f"User registered successfully: {username}"
                            }

                except Exception as e:
                    logger.error(f"[{client_id}] Database error during registration: {e}")
                    response = {
                        "type": "register_response",
                        "success": False,
                        "message": "Database error during registration"
                    }

                # Send response
                response_json = json.dumps(response, separators=(",", ":"))
                response_bytes = response_json.encode('utf-8')
                client_socket.sendall(
                    len(response_bytes).to_bytes(4, byteorder='big') + response_bytes
                )
                logger.debug(f"[{client_id}] Sent registration response")
                print(f"[{client_id}] [*] Sent response to client - closing connection")

            except json.JSONDecodeError as e:
                logger.error(f"[{client_id}] Failed to parse decrypted registration data: {e}")
                response = {
                    "type": "register_response",
                    "success": False,
                    "message": "Invalid registration data format"
                }
                response_json = json.dumps(response, separators=(",", ":"))
                response_bytes = response_json.encode('utf-8')
                client_socket.sendall(
                    len(response_bytes).to_bytes(4, byteorder='big') + response_bytes
                )
            except Exception as e:
                logger.error(f"[{client_id}] Decryption/processing error: {e}")
                response = {
                    "type": "register_response",
                    "success": False,
                    "message": "Processing error"
                }
                response_json = json.dumps(response, separators=(",", ":"))
                response_bytes = response_json.encode('utf-8')
                client_socket.sendall(
                    len(response_bytes).to_bytes(4, byteorder='big') + response_bytes
                )

        elif msg_type == 'LOGIN_ENCRYPTED':
            logger.info(f"[{client_id}] Processing encrypted login request")
            print(f"[{client_id}] [*] Processing login request...")

            try:
                # Step 1: Decrypt login data
                ciphertext_b64 = msg_dict.get('ciphertext')
                if not ciphertext_b64:
                    logger.error(f"[{client_id}] LOGIN_ENCRYPTED missing ciphertext")
                    response = {
                        "type": "login_response",
                        "success": False,
                        "username": None,
                        "message": "Invalid login message"
                    }
                    response_json = json.dumps(response, separators=(",", ":"))
                    response_bytes = response_json.encode('utf-8')
                    client_socket.sendall(
                        len(response_bytes).to_bytes(4, byteorder='big') + response_bytes
                    )
                    return

                ciphertext = base64.b64decode(ciphertext_b64)
                plaintext = aes_decrypt(ciphertext, session_key)
                login_data = json.loads(plaintext)
                
                logger.debug(f"[{client_id}] Decrypted login data successfully")
                print(f"[{client_id}] [+] Decrypted login payload")

                # Step 2: Extract fields
                email = login_data.get('email', '').strip()
                password = login_data.get('password', '').strip()

                if not email or not password:
                    logger.warning(f"[{client_id}] Login data missing email or password")
                    response = {
                        "type": "login_response",
                        "success": False,
                        "username": None,
                        "message": "Missing email or password"
                    }
                    response_json = json.dumps(response, separators=(",", ":"))
                    response_bytes = response_json.encode('utf-8')
                    client_socket.sendall(
                        len(response_bytes).to_bytes(4, byteorder='big') + response_bytes
                    )
                    return

                logger.info(f"[{client_id}] [GATE 1] Certificate already validated during cert exchange")
                print(f"[{client_id}] [GATE 1] ✓ Certificate valid")

                # Step 3: Get database connection and verify password
                try:
                    db_conn = get_connection()
                except Exception as e:
                    logger.error(f"[{client_id}] Failed to get database connection: {e}")
                    response = {
                        "type": "login_response",
                        "success": False,
                        "username": None,
                        "message": "Database connection failed"
                    }
                    response_json = json.dumps(response, separators=(",", ":"))
                    response_bytes = response_json.encode('utf-8')
                    client_socket.sendall(
                        len(response_bytes).to_bytes(4, byteorder='big') + response_bytes
                    )
                    return

                # Step 4: GATE 2 - Verify password hash
                logger.info(f"[{client_id}] [GATE 2] Verifying password hash...")
                print(f"[{client_id}] [GATE 2] Verifying password hash...")
                
                try:
                    success, username = verify_login(email, password, db_conn)
                finally:
                    try:
                        db_conn.close()
                    except:
                        pass

                if success:
                    logger.info(f"[{client_id}] [GATE 2] ✓ Password verified for user {username}")
                    print(f"[{client_id}] [GATE 2] ✓ Password verified for user {username}")
                    
                    logger.info(f"[{client_id}] [AUTH COMPLETE] Dual-gate authentication succeeded: {username}")
                    print(f"[{client_id}] [+] Dual-gate authentication successful!")
                    print(f"[{client_id}]     User: {username} ({email})")
                    print(f"[{client_id}]     ✓ Certificate valid (gate 1)")
                    print(f"[{client_id}]     ✓ Password verified (gate 2)")
                    print(f"[{client_id}] [*] Session authenticated - ready for chat...")

                    response = {
                        "type": "login_response",
                        "success": True,
                        "username": username,
                        "message": f"Login successful: {username}"
                    }
                    
                    # Send response
                    response_json = json.dumps(response, separators=(",", ":"))
                    response_bytes = response_json.encode('utf-8')
                    client_socket.sendall(
                        len(response_bytes).to_bytes(4, byteorder='big') + response_bytes
                    )
                    
                    logger.debug(f"[{client_id}] Sent successful login response")
                    print(f"[{client_id}] [+] Sent login response - keeping connection open")
                    
                    # Initiate chat session DH exchange
                    logger.info(f"[{client_id}] Initiating chat session DH key exchange")
                    print(f"[{client_id}] [*] Initiating chat session key exchange...")
                    
                    # Generate fresh DH keypair for chat session
                    chat_dh_private, chat_dh_public = generate_dh_keypair()
                    logger.debug(f"[{client_id}] Generated fresh DH keypair for chat session")
                    print(f"[{client_id}] [+] Generated fresh DH keypair")
                    
                    # Receive DH_CLIENT from client
                    logger.info(f"[{client_id}] Waiting for DH_CLIENT from client (chat session)")
                    length_bytes = client_socket.recv(4)
                    if not length_bytes:
                        logger.warning(f"[{client_id}] Client closed connection during chat DH exchange")
                        return
                    
                    msg_len = int.from_bytes(length_bytes, byteorder='big')
                    if msg_len > 1024 * 1024:
                        logger.error(f"[{client_id}] DH_CLIENT message too large: {msg_len}")
                        return
                    
                    msg_bytes = b''
                    while len(msg_bytes) < msg_len:
                        chunk = client_socket.recv(msg_len - len(msg_bytes))
                        if not chunk:
                            logger.error(f"[{client_id}] Connection closed while reading DH_CLIENT")
                            return
                        msg_bytes += chunk
                    
                    msg_json = msg_bytes.decode('utf-8')
                    dh_client_msg = json.loads(msg_json)
                    
                    if dh_client_msg.get('type') != 'DH_CLIENT':
                        logger.error(f"[{client_id}] Expected DH_CLIENT, got {dh_client_msg.get('type')}")
                        return
                    
                    client_dh_public = int(dh_client_msg['dh_public'], 16)
                    logger.debug(f"[{client_id}] Received DH_CLIENT with client public key")
                    print(f"[{client_id}] [+] Received DH_CLIENT from client")
                    
                    # Compute shared secret and derive chat session key
                    chat_shared_secret = compute_shared_secret(chat_dh_private, client_dh_public)
                    chat_session_key = chat_shared_secret  # Already 16 bytes from compute_shared_secret
                    
                    logger.debug(f"[{client_id}] Chat session key derived: {chat_session_key.hex()[:16]}...")
                    print(f"[{client_id}] [+] Chat session key derived: {chat_session_key.hex()[:16]}...")
                    
                    # Send DH_SERVER with server's public key
                    dh_server_response = {
                        "type": "DH_SERVER",
                        "dh_public": hex(chat_dh_public)
                    }
                    
                    msg_json = json.dumps(dh_server_response)
                    msg_bytes = msg_json.encode('utf-8')
                    client_socket.sendall(
                        len(msg_bytes).to_bytes(4, byteorder='big') + msg_bytes
                    )
                    
                    logger.info(f"[{client_id}] Sent DH_SERVER for chat session")
                    print(f"[{client_id}] [+] Sent DH_SERVER to client")
                    
                    # Initialize chat session state
                    chat_seqno = 0
                    logger.info(f"[{client_id}] Chat session established: {username}")
                    print(f"[{client_id}] [+] Secure chat session established with {username}")
                    print(f"[{client_id}]     Session key: {chat_session_key.hex()[:16]}...")
                    print(f"[{client_id}]     Sequence number: {chat_seqno}")
                    
                    # Set socket timeout for both threads to avoid blocking forever
                    client_socket.settimeout(1.0)
                    
                    # Start receiving messages in a thread
                    receive_thread = threading.Thread(
                        target=receive_chat_messages,
                        args=(client_socket, client_id, username, chat_session_key, client_cert_pem),
                        daemon=False
                    )
                    receive_thread.start()
                    
                    # Run server message sending loop (blocks until exit)
                    send_chat_message_loop(client_socket, client_id, username, chat_session_key, server_key_pem, server_cert_pem)
                    
                    # Wait for receive thread to finish
                    receive_thread.join(timeout=5)
                    if receive_thread.is_alive():
                        logger.warning(f"[{client_id}] Receive thread still running, closing socket")
                    
                    logger.info(f"[{client_id}] Chat session ended for {username}")
                    return
                    
                else:
                    logger.warning(f"[{client_id}] [GATE 2] ✗ Password verification failed for {email}")
                    print(f"[{client_id}] [GATE 2] ✗ Password verification failed")
                    
                    response = {
                        "type": "login_response",
                        "success": False,
                        "username": None,
                        "message": "Invalid email or password"
                    }
                    
                    response_json = json.dumps(response, separators=(",", ":"))
                    response_bytes = response_json.encode('utf-8')
                    client_socket.sendall(
                        len(response_bytes).to_bytes(4, byteorder='big') + response_bytes
                    )
                    
                    logger.debug(f"[{client_id}] Sent failed login response")
                    print(f"[{client_id}] [*] Sent login response - closing connection")
                    return

            except json.JSONDecodeError as e:
                logger.error(f"[{client_id}] Failed to parse decrypted login data: {e}")
                response = {
                    "type": "login_response",
                    "success": False,
                    "username": None,
                    "message": "Invalid login data format"
                }
                response_json = json.dumps(response, separators=(",", ":"))
                response_bytes = response_json.encode('utf-8')
                client_socket.sendall(
                    len(response_bytes).to_bytes(4, byteorder='big') + response_bytes
                )
                return
            except Exception as e:
                logger.error(f"[{client_id}] Decryption/processing error: {e}")
                response = {
                    "type": "login_response",
                    "success": False,
                    "username": None,
                    "message": "Processing error"
                }
                response_json = json.dumps(response, separators=(",", ":"))
                response_bytes = response_json.encode('utf-8')
                client_socket.sendall(
                    len(response_bytes).to_bytes(4, byteorder='big') + response_bytes
                )
                return

        else:
            logger.warning(f"[{client_id}] Unknown message type after DH exchange: {msg_type}")
            print(f"[{client_id}] [!] Unknown message type: {msg_type}")

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
                handle_client(client_socket, client_address, cert_pem, key_pem)

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
