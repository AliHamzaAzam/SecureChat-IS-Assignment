"""
User registration and authentication utilities.

This module provides secure user registration and login verification with proper
password hashing and constant-time comparison to prevent timing attacks.

Password Security:
    - Salt: 16-byte random value per user (prevents rainbow table attacks)
    - Hash: SHA-256 of (salt + password) (cryptographically secure)
    - Comparison: secrets.compare_digest() (constant-time, prevents timing attacks)

Database Schema Expected:
    CREATE TABLE users (
        email VARCHAR(255) PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        salt BINARY(16) NOT NULL,
        pwd_hash VARCHAR(64) NOT NULL
    );

Usage:
    from app.storage.db import get_connection
    from app.server.registration import register_user, verify_login

    db = get_connection()

    # Register a new user
    success, message = register_user("alice@example.com", "alice", "password123", db)
    if success:
        print(f"Registered: {message}")
    else:
        print(f"Error: {message}")

    # Verify login
    success, username = verify_login("alice@example.com", "password123", db)
    if success:
        print(f"Login successful: {username}")
    else:
        print("Login failed")

Security Considerations:
    - Passwords are never logged or printed
    - Salt is randomly generated per user (prevents duplicate hashes)
    - Constant-time comparison prevents timing attacks during login
    - Database errors don't leak information (generic error messages)
"""

import hashlib
import secrets
from typing import Tuple, Optional
import mysql.connector


def _hash_password(salt: bytes, password: str) -> str:
    """
    Compute SHA-256 hash of salt + password.

    Args:
        salt: 16-byte salt value
        password: User's password string

    Returns:
        str: 64-character hexadecimal SHA-256 digest

    Raises:
        TypeError: If salt is not bytes or password is not str
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
    Register a new user with secure password hashing.

    Generates a 16-byte random salt, computes SHA-256 hash of salt + password,
    and stores in database if email and username don't already exist.

    Args:
        email: User's email address (will be primary key)
        username: Display name (must be unique)
        password: User's password (will be hashed with salt)
        db_connection: MySQL database connection

    Returns:
        Tuple of (success: bool, message: str)
        - On success: (True, "User registered successfully: <username>")
        - On failure: (False, "<error_message>")

    Raises:
        TypeError: If arguments are of wrong type
        AttributeError: If db_connection is not a valid connection

    Example:
        >>> from app.storage.db import get_connection
        >>> db = get_connection()
        >>> success, msg = register_user("bob@example.com", "bob", "pass123", db)
        >>> if success:
        ...     print("Registered:", msg)
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
    Verify user login credentials with constant-time comparison.

    Retrieves stored salt and pwd_hash, recomputes hash with provided password,
    and uses secrets.compare_digest() for secure comparison.

    Args:
        email: User's email address
        password: Password to verify
        db_connection: MySQL database connection

    Returns:
        Tuple of (success: bool, username: str or None)
        - On success: (True, "<username>")
        - On failure: (False, None)

    Raises:
        TypeError: If arguments are of wrong type
        AttributeError: If db_connection is not a valid connection

    Example:
        >>> from app.storage.db import get_connection
        >>> db = get_connection()
        >>> success, username = verify_login("bob@example.com", "pass123", db)
        >>> if success:
        ...     print(f"Welcome, {username}!")
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
