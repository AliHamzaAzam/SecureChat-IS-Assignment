"""
Protocol message definitions for SecureChat.

Defines dataclasses for all message types (HELLO, DH, MSG, RECEIPT) serialized
to/from JSON. All messages use length-prefixed framing over TCP.
"""

from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Optional
import json


class MessageType(Enum):
    """Message types in the SecureChat protocol."""

    HELLO = "HELLO"
    SERVER_HELLO = "SERVER_HELLO"
    REGISTER = "REGISTER"
    LOGIN = "LOGIN"
    DH_CLIENT = "DH_CLIENT"
    DH_SERVER = "DH_SERVER"
    MSG = "MSG"
    RECEIPT = "RECEIPT"

    def __str__(self) -> str:
        return self.value


@dataclass
class ControlPlaneMsg:
    """
    Control plane message for handshake and key exchange.

    Used for HELLO, SERVER_HELLO, REGISTER, and LOGIN messages.

    Fields:
        type: MessageType enum value
        client_cert: PEM-encoded X.509 client certificate (optional)
        server_cert: PEM-encoded X.509 server certificate (optional)
        nonce: Random bytes (base64-encoded) for replay protection
        username: Username for REGISTER and LOGIN (optional)
        password: Password for REGISTER and LOGIN (optional, never logged)
    """

    type: str  # MessageType.value
    nonce: str  # base64-encoded random bytes
    client_cert: Optional[str] = None  # PEM format
    server_cert: Optional[str] = None  # PEM format
    username: Optional[str] = None
    password: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary, excluding None values."""
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class DHClientMsg:
    """
    Diffie-Hellman client initiation message.

    Client sends its DH public key to server. The server will use this along
    with its private key to compute the shared session key.

    Fields:
        type: MessageType.DH_CLIENT
        g: DH generator (2 for RFC 3526 Group 14)
        p: DH prime (2048-bit safe prime, as hex string)
        A: Client's DH public key (as hex string)
    """

    type: str  # "DH_CLIENT"
    g: int
    p: str  # hex string of 2048-bit prime
    A: str  # hex string of client's public key

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class DHServerMsg:
    """
    Diffie-Hellman server response message.

    Server sends its DH public key to client. Client will use this along
    with its private key to compute the shared session key (same as server's).

    Fields:
        type: MessageType.DH_SERVER
        B: Server's DH public key (as hex string)
    """

    type: str  # "DH_SERVER"
    B: str  # hex string of server's public key

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class ChatMsg:
    """
    Encrypted chat message.

    Contains an AES-128 CBC encrypted message, along with a sequence number,
    timestamp, and RSA-PSS signature for authentication and non-repudiation.

    Fields:
        type: MessageType.MSG
        seqno: Sequence number (increments per message)
        ts: Timestamp in milliseconds (UNIX epoch)
        ct: Ciphertext base64-encoded (includes IV prepended)
        sig: RSA-PSS signature base64-encoded
    """

    type: str  # "MSG"
    seqno: int
    ts: int  # milliseconds since epoch
    ct: str  # base64-encoded ciphertext
    sig: str  # base64-encoded RSA-PSS signature

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class SessionReceipt:
    """
    Session receipt for non-repudiation proof.

    Sent by either party to create a cryptographic proof of the session.
    Includes the range of sequence numbers, hash of transcript, and signature.

    Fields:
        type: MessageType.RECEIPT
        peer: Email of peer in the session
        first_seq: First sequence number in session
        last_seq: Last sequence number in session
        transcript_sha256: SHA-256 of concatenated encrypted messages (hex string)
        sig: RSA-PSS signature over (peer + first_seq + last_seq + transcript_sha256)
    """

    type: str  # "RECEIPT"
    peer: str  # Email of communication peer
    first_seq: int
    last_seq: int
    transcript_sha256: str  # hex string of SHA-256 digest
    sig: str  # base64-encoded RSA-PSS signature

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)


def serialize_message(msg_obj) -> str:
    """
    Serialize message dataclass to JSON string.
    
    Calls to_dict() method or uses asdict() if unavailable.
    
    Returns: Compact JSON string
    Raises: TypeError, ValueError
    """
    try:
        if hasattr(msg_obj, "to_dict"):
            # Use custom to_dict method if available
            msg_dict = msg_obj.to_dict()
        else:
            # Fallback to asdict for generic dataclasses
            msg_dict = asdict(msg_obj)

        # Serialize to JSON
        json_str = json.dumps(msg_dict, separators=(",", ":"))
        return json_str

    except TypeError as e:
        raise TypeError(f"Cannot serialize non-dataclass object: {type(msg_obj).__name__}") from e
    except Exception as e:
        raise ValueError(f"JSON serialization failed: {e}") from e


def deserialize_message(json_str: str) -> dict:
    """
    Deserialize JSON string to dictionary.
    
    Returns: Message dictionary
    Raises: json.JSONDecodeError, ValueError
    """
    if not isinstance(json_str, str):
        raise TypeError(f"json_str must be string, got {type(json_str)}")

    try:
        msg_dict = json.loads(json_str)
        if not isinstance(msg_dict, dict):
            raise ValueError("JSON must deserialize to a dictionary")
        return msg_dict
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}") from e


def message_dict_to_obj(msg_dict: dict):
    """
    Convert message dictionary to appropriate dataclass instance.
    
    Uses 'type' field to determine which dataclass to instantiate.
    
    Returns: Dataclass instance or None if unknown type
    """
    if not isinstance(msg_dict, dict):
        raise TypeError(f"msg_dict must be dict, got {type(msg_dict)}")

    msg_type = msg_dict.get("type")
    if not msg_type:
        raise ValueError("Message dict missing required 'type' field")

    try:
        msg_enum = MessageType(msg_type)
    except ValueError:
        raise ValueError(f"Unknown message type: {msg_type}")

    try:
        if msg_enum in (MessageType.HELLO, MessageType.SERVER_HELLO, MessageType.REGISTER, MessageType.LOGIN):
            return ControlPlaneMsg(**msg_dict)
        elif msg_enum == MessageType.DH_CLIENT:
            return DHClientMsg(**msg_dict)
        elif msg_enum == MessageType.DH_SERVER:
            return DHServerMsg(**msg_dict)
        elif msg_enum == MessageType.MSG:
            return ChatMsg(**msg_dict)
        elif msg_enum == MessageType.RECEIPT:
            return SessionReceipt(**msg_dict)
        else:
            raise ValueError(f"Unhandled message type: {msg_type}")
    except TypeError as e:
        raise ValueError(f"Missing required fields for message type {msg_type}: {e}") from e


def get_message_type(json_str: str) -> str:
    """
    Extract message type from JSON string without full deserialization.

    Useful for quick type checking before parsing entire message.

    Args:
        json_str: JSON-formatted message string

    Returns:
        str: Message type value (e.g., "HELLO", "MSG")

    Raises:
        ValueError: If JSON is malformed or type field missing

    Example:
        >>> json_str = '{"type": "LOGIN", "nonce": "abc123"}'
        >>> get_message_type(json_str)
        'LOGIN'
    """
    try:
        msg_dict = json.loads(json_str)
        msg_type = msg_dict.get("type")
        if not msg_type:
            raise ValueError("Message missing 'type' field")
        return msg_type
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}") from e
