-- SecureChat Sample Database and Data
-- This file creates the database, schema, and populates sample user data
-- for demonstration and testing purposes.

-- ============================================================================
-- CREATE DATABASE
-- ============================================================================

CREATE DATABASE IF NOT EXISTS securechat
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE securechat;

-- ============================================================================
-- CREATE TABLE: users
-- ============================================================================
-- Schema: email (VARCHAR PK), username (VARCHAR unique), salt (VARBINARY),
--         pwd_hash (CHAR 64), created_at (TIMESTAMP), updated_at (TIMESTAMP)
--
-- Security Notes:
-- - pwd_hash: SHA-256(password + salt), stored as hex string (64 chars)
-- - salt: Random binary data (16 bytes)
-- - email: Primary key, user email address
-- - Timestamps track account lifecycle
-- ============================================================================

CREATE TABLE IF NOT EXISTS users (
  email VARCHAR(255) NOT NULL PRIMARY KEY COMMENT 'User email address',
  username VARCHAR(100) NOT NULL UNIQUE COMMENT 'Unique username',
  salt VARBINARY(16) NOT NULL COMMENT 'Password salt for hashing',
  pwd_hash CHAR(64) NOT NULL COMMENT 'SHA-256 password hash (hex)',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Account creation time',
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Last update time',
  
  INDEX idx_username (username),
  INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='User account credentials with salted SHA-256 password hashes';

-- ============================================================================
-- SAMPLE DATA: User Accounts
-- ============================================================================
-- Users: alice, bob, charlie, demo_user, test_user
-- All passwords use example hashes (in production, generate using proper hashing)
--
-- Generation Method (Python):
--   import hashlib
--   password = "password123"
--   salt = os.urandom(16)  # 16 bytes binary
--   pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
--
-- Note: salt is stored as binary; example hashes shown as hex for readability
-- ============================================================================

INSERT INTO users (email, username, salt, pwd_hash) VALUES
('alice@example.com', 'alice', UNHEX('4be97c9f40102e463d26c9c0c0a1'), '05b64b59bb92451df7fddb850ed01c797135907994c11b7b7d8d9ffd6a95f47e'),
('bob@example.com', 'bob', UNHEX('324365d5c9ed9a27c9515165ba2a'), '1956841916d9cf88ac4a39f939536f49a09ed41f33f15a10b00eceeefa30b95e'),
('charlie@example.com', 'charlie', UNHEX('c9c0265ce94f047ea8b9cc2701b2'), '667dfcd82b54f2107ea8b9cc2701b24d2f6691ca5494b60d30f9efed5c721453'),
('demo@example.com', 'demo_user', UNHEX('31c9c05c37c0cc736d9bacbac4e4'), '4bd7c4e77937c0616a2ee4555db5fd5c26cfa1384485be6b090e8978713b01be'),
('test@example.com', 'test_user', UNHEX('a5c965d8e5cc376b4f7d00e30c9a'), 'f4a9c9e8d1e2b3f4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7');

-- ============================================================================
-- VERIFICATION
-- ============================================================================
-- Run this query to verify sample data was inserted:
--   SELECT email, username, created_at FROM users;
--
-- Expected output:
-- | email               | username   | created_at          |
-- |---------------------|------------|---------------------|
-- | alice@example.com   | alice      | [timestamp]         |
-- | bob@example.com     | bob        | [timestamp]         |
-- | charlie@example.com | charlie    | [timestamp]         |
-- | demo@example.com    | demo_user  | [timestamp]         |
-- | test@example.com    | test_user  | [timestamp]         |
-- ============================================================================
