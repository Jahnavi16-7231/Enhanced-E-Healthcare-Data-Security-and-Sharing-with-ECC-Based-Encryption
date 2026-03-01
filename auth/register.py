# auth/register.py

import sqlite3
import bcrypt
from crypto.ecc_crypto import generate_ecc_key_pair
from config import DATABASE


def register_user(name, email, password, role):
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    private_key, public_key = generate_ecc_key_pair()

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO users (name, email, password_hash, role, ecc_public_key)
        VALUES (?, ?, ?, ?, ?)
    """, (
        name,
        email,
        password_hash.decode(),
        role,
        public_key
    ))

    conn.commit()
    conn.close()

    # give private key to user (NOT stored in DB)
    return private_key
