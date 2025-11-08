"""
Database manager for MySQL operations.

This module provides functions to:
- Initialize the database and create tables
- Establish connections to MySQL
- Close connections safely
- Handle connection errors gracefully
"""

import os
import sys
from typing import Optional
import mysql.connector
from mysql.connector import Error, pooling


# Connection pool configuration
_connection_pool: Optional[pooling.MySQLConnectionPool] = None


def _get_db_config() -> dict:
    """
    Get database configuration from environment variables.

    Returns:
        Dictionary with host, user, password, database settings

    Raises:
        ValueError: If required environment variables are missing
    """
    required_vars = {
        "MYSQL_HOST": os.getenv("MYSQL_HOST", "localhost"),
        "MYSQL_USER": os.getenv("MYSQL_USER", "scuser"),
        "MYSQL_PASSWORD": os.getenv("MYSQL_PASSWORD", "scpass"),
        "MYSQL_DATABASE": os.getenv("MYSQL_DATABASE", "securechat"),
    }

    # Check for missing critical variables
    for key, value in required_vars.items():
        if not value:
            raise ValueError(f"Missing required environment variable: {key}")

    return required_vars


def init_database() -> bool:
    """
    Initialize the database and create necessary tables.

    This function:
    1. Creates the 'securechat' database if it doesn't exist
    2. Creates the 'users' table with proper schema
    3. Handles duplicate database/table errors gracefully

    Returns:
        True if successful, False otherwise

    Raises:
        ValueError: If database configuration is missing
    """
    try:
        config = _get_db_config()
        print("[*] Connecting to MySQL server...")

        # Connect without specifying database (to create it)
        conn = mysql.connector.connect(
            host=config["MYSQL_HOST"],
            user=config["MYSQL_USER"],
            password=config["MYSQL_PASSWORD"],
        )
        cursor = conn.cursor()
        print("[✓] Connected to MySQL server")

        # Create database
        print(f"[*] Creating database '{config['MYSQL_DATABASE']}'...")
        cursor.execute(
            f"CREATE DATABASE IF NOT EXISTS `{config['MYSQL_DATABASE']}`"
        )
        print(f"[✓] Database '{config['MYSQL_DATABASE']}' ready")

        # Switch to the database
        cursor.execute(f"USE `{config['MYSQL_DATABASE']}`")

        # Create users table
        print("[*] Creating 'users' table...")
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS users (
            email VARCHAR(255) PRIMARY KEY COMMENT 'User email address',
            username VARCHAR(100) UNIQUE NOT NULL COMMENT 'Unique username',
            salt VARBINARY(16) NOT NULL COMMENT 'Password salt for hashing',
            pwd_hash CHAR(64) NOT NULL COMMENT 'SHA-256 password hash (hex)',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Account creation time',
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Last update time'
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        COMMENT='User account credentials with salted SHA-256 password hashes';
        """

        cursor.execute(create_table_sql)
        print("[✓] 'users' table created")

        # Verify table structure
        cursor.execute("DESCRIBE users")
        columns = cursor.fetchall()
        print("[*] Table schema:")
        for col in columns:
            print(f"    {col[0]}: {col[1]}")

        cursor.close()
        conn.commit()
        conn.close()

        print("\n" + "=" * 60)
        print("[✓] Database initialization completed successfully!")
        print("=" * 60 + "\n")
        return True

    except Error as err:
        if err.errno == 1049:
            print(f"[✗] Database error: {err.msg}", file=sys.stderr)
        else:
            print(f"[✗] MySQL Error: {err}", file=sys.stderr)
        return False
    except ValueError as err:
        print(f"[✗] Configuration Error: {err}", file=sys.stderr)
        return False
    except Exception as err:
        print(f"[✗] Unexpected error: {err}", file=sys.stderr)
        return False


def get_connection():
    """
    Get a connection from the connection pool.

    Initializes the connection pool on first call if needed.

    Returns:
        mysql.connector.MySQLConnection object

    Raises:
        ValueError: If database configuration is missing
        Error: If connection fails
    """
    global _connection_pool

    try:
        config = _get_db_config()

        # Initialize pool if not already done
        if _connection_pool is None:
            print("[*] Initializing connection pool...")
            _connection_pool = pooling.MySQLConnectionPool(
                pool_name="securechat_pool",
                pool_size=5,
                pool_reset_session=True,
                host=config["MYSQL_HOST"],
                user=config["MYSQL_USER"],
                password=config["MYSQL_PASSWORD"],
                database=config["MYSQL_DATABASE"],
            )
            print("[✓] Connection pool initialized")

        # Get connection from pool
        connection = _connection_pool.get_connection()
        return connection

    except Error as err:
        print(f"[✗] MySQL Connection Error: {err}", file=sys.stderr)
        raise
    except ValueError as err:
        print(f"[✗] Configuration Error: {err}", file=sys.stderr)
        raise


def close_connection(conn) -> bool:
    """
    Close a database connection safely.

    Args:
        conn: mysql.connector.MySQLConnection object

    Returns:
        True if successfully closed, False otherwise
    """
    try:
        if conn and conn.is_connected():
            conn.close()
            return True
        return False
    except Error as err:
        print(f"[✗] Error closing connection: {err}", file=sys.stderr)
        return False


def test_connection() -> bool:
    """
    Test the database connection.

    Returns:
        True if connection successful, False otherwise
    """
    try:
        print("[*] Testing database connection...")
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        result = cursor.fetchone()
        cursor.close()
        close_connection(conn)
        print("[✓] Database connection test successful")
        return result is not None
    except Exception as err:
        print(f"[✗] Connection test failed: {err}", file=sys.stderr)
        return False


if __name__ == "__main__":
    # For standalone testing
    from pathlib import Path

    # Load environment variables
    env_file = Path(__file__).parent.parent.parent / ".env"
    if env_file.exists():
        from dotenv import load_dotenv
        load_dotenv(env_file)
        print(f"[*] Loaded environment from {env_file}")
    else:
        print(f"[!] Warning: .env file not found at {env_file}")

    if len(sys.argv) > 1 and sys.argv[1] == "--init":
        init_database()
    elif len(sys.argv) > 1 and sys.argv[1] == "--test":
        test_connection()
    else:
        print("Usage: python -m app.storage.db [--init|--test]")
