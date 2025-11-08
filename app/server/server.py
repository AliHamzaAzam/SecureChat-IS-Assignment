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
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# Handle imports whether run as module or script
try:
    from app.common.protocol import ControlPlaneMsg, MessageType, serialize_message, deserialize_message, DHClientMsg, DHServerMsg
    from app.crypto.cert_validator import load_certificate, load_certificate_from_pem_string, validate_certificate
    from app.crypto.dh_exchange import generate_dh_keypair, compute_shared_secret, get_dh_params
    from app.crypto.aes_crypto import aes_decrypt
    from app.server.registration import register_user, verify_login
    from app.storage.db import get_connection
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from app.common.protocol import ControlPlaneMsg, MessageType, serialize_message, deserialize_message, DHClientMsg, DHServerMsg
    from app.crypto.cert_validator import load_certificate, load_certificate_from_pem_string, validate_certificate
    from app.crypto.dh_exchange import generate_dh_keypair, compute_shared_secret, get_dh_params
    from app.crypto.aes_crypto import aes_decrypt
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
                    
                    # TODO: Transition to chat session mode (keep connection open)
                    # For now, close the connection gracefully
                    logger.info(f"[{client_id}] Authenticated session - ready for chat messages")
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
