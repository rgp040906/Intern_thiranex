import sqlite3
import os

DB_FILE = "passwords.db"

def init_db():
    """Initializes the database table if it doesn't exist."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS previous_hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_hash TEXT UNIQUE NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def is_hash_used(password_hash: str) -> bool:
    """Checks if a password hash has been used before."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM previous_hashes WHERE password_hash = ?', (password_hash,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def store_hash(password_hash: str) -> bool:
    """Stores a new password hash. Returns True if successful, False if already exists."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO previous_hashes (password_hash) VALUES (?)', (password_hash,))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False
