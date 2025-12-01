"""
User registration and authentication utilities.

This module provides secure user registration and login verification with proper
User registration and authentication with salted SHA-256 password hashing.

Security: Random per-user salts, constant-time comparison (prevents timing attacks).
"""

import hashlib
import secrets
from typing import Tuple, Optional
import mysql.connector


def _hash_password(salt: bytes, password: str) -> str:
    """
    Compute SHA-256 hash of salt + password.
    
    Returns: 64-char hex digest
    Raises: TypeError
    """
    if not isinstance(salt, bytes):
        raise TypeError(f"salt must be bytes, got {type(salt)}")

    if not isinstance(password, str):
        raise TypeError(f"password must be str, got {type(password)}")

    # Concatenate salt and password bytes
    hash_input = salt + password.encode("utf-8")

    # Compute SHA-256
    digest = hashlib.sha256(hash_input).hexdigest()

    return digest


def register_user(
    email: str,
    username: str,
    password: str,
    db_connection,
) -> Tuple[bool, str]:
    """
    Register new user with salted SHA-256 password hash.
    
    Generates random 16-byte salt, computes hash, stores if email/username available.
    
    Args: email, username, password, db_connection
    Returns: (success: bool, message: str)
    """
    # Input validation
    if not isinstance(email, str):
        raise TypeError(f"email must be str, got {type(email)}")

    if not isinstance(username, str):
        raise TypeError(f"username must be str, got {type(username)}")

    if not isinstance(password, str):
        raise TypeError(f"password must be str, got {type(password)}")

    if not email or not username or not password:
        return False, "Email, username, and password cannot be empty"

    try:
        # Generate 16-byte random salt
        salt = secrets.token_bytes(16)

        # Compute password hash
        pwd_hash = _hash_password(salt, password)

        # Create database cursor
        cursor = db_connection.cursor()

        # Check if email already exists
        cursor.execute("SELECT email FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            cursor.close()
            return False, f"Email already registered: {email}"

        # Check if username already exists
        cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            cursor.close()
            return False, f"Username already taken: {username}"

        # Insert new user
        cursor.execute(
            "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
            (email, username, salt, pwd_hash),
        )
        db_connection.commit()
        cursor.close()

        return True, f"User registered successfully: {username}"

    except mysql.connector.Error as e:
        # Database error - don't leak details
        error_code = e.errno if hasattr(e, "errno") else "unknown"
        return False, f"Database error during registration (code: {error_code})"

    except Exception as e:
        # Unexpected error
        return False, f"Unexpected error during registration: {type(e).__name__}"


def verify_login(
    email: str,
    password: str,
    db_connection,
) -> Tuple[bool, Optional[str]]:
    """
    Verify login with constant-time comparison.
    
    Retrieves salt+hash, recomputes hash, uses secrets.compare_digest() for secure comparison.
    
    Args: email, password, db_connection
    Returns: (success: bool, username: str or None)
    """
    # Input validation
    if not isinstance(email, str):
        raise TypeError(f"email must be str, got {type(email)}")

    if not isinstance(password, str):
        raise TypeError(f"password must be str, got {type(password)}")

    if not email or not password:
        return False, None

    try:
        # Create database cursor
        cursor = db_connection.cursor()

        # Retrieve user record
        cursor.execute(
            "SELECT username, salt, pwd_hash FROM users WHERE email = %s",
            (email,),
        )
        result = cursor.fetchone()
        cursor.close()

        if not result:
            # User not found - return generic failure
            return False, None

        username, salt, stored_hash = result

        # Recompute hash with provided password
        computed_hash = _hash_password(salt, password)

        # Constant-time comparison (prevents timing attacks)
        if secrets.compare_digest(computed_hash, stored_hash):
            return True, username
        else:
            return False, None

    except mysql.connector.Error as e:
        # Database error - don't leak details, return generic failure
        return False, None

    except Exception as e:
        # Unexpected error - return generic failure
        return False, None


def get_salt_from_db(email: str, db_connection) -> Optional[bytes]:
    """
    Retrieve salt for a user (for debugging/testing only).

    WARNING: This function is provided for testing and debugging purposes only.
    In production, salt should never be exposed to clients.

    Args:
        email: User's email address
        db_connection: MySQL database connection

    Returns:
        bytes: 16-byte salt, or None if user not found

    Raises:
        mysql.connector.Error: If database query fails
    """
    cursor = db_connection.cursor()
    cursor.execute("SELECT salt FROM users WHERE email = %s", (email,))
    result = cursor.fetchone()
    cursor.close()

    if result:
        return result[0]
    return None


def user_exists(email: str, db_connection) -> bool:
    """
    Check if a user exists in the database.

    Args:
        email: User's email address
        db_connection: MySQL database connection

    Returns:
        bool: True if user exists, False otherwise

    Raises:
        mysql.connector.Error: If database query fails
    """
    try:
        cursor = db_connection.cursor()
        cursor.execute("SELECT email FROM users WHERE email = %s", (email,))
        result = cursor.fetchone()
        cursor.close()
        return result is not None
    except mysql.connector.Error:
        return False


def username_exists(username: str, db_connection) -> bool:
    """
    Check if a username exists in the database.

    Args:
        username: Username to check
        db_connection: MySQL database connection

    Returns:
        bool: True if username exists, False otherwise

    Raises:
        mysql.connector.Error: If database query fails
    """
    try:
        cursor = db_connection.cursor()
        cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()
        cursor.close()
        return result is not None
    except mysql.connector.Error:
        return False
