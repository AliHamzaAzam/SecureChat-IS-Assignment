-- SecureChat Database Schema
-- This file documents the database structure for the SecureChat application

-- Create database
CREATE DATABASE IF NOT EXISTS securechat
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

-- Use the database
USE securechat;

-- Users table with salted SHA-256 password hashes
CREATE TABLE IF NOT EXISTS users (
    email VARCHAR(255) PRIMARY KEY COMMENT 'User email address',
    username VARCHAR(100) UNIQUE NOT NULL COMMENT 'Unique username',
    salt VARBINARY(16) NOT NULL COMMENT 'Password salt for hashing',
    pwd_hash CHAR(64) NOT NULL COMMENT 'SHA-256 password hash (hex)',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Account creation time',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Last update time'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='User account credentials with salted SHA-256 password hashes';

-- Create indexes for efficient queries
CREATE INDEX idx_username ON users(username);
CREATE INDEX idx_created_at ON users(created_at);

-- Sample data (for testing)
-- INSERT INTO users (email, username, salt, pwd_hash)
-- VALUES ('alice@example.com', 'alice', 0x1234567890ABCDEF, 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3');
