# auth/login.py

import sqlite3
import bcrypt
from config import DATABASE


def login_user(email, password):
    """
    Authenticates user using hashed password
    """

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, name, password_hash, role, ecc_public_key
        FROM users
        WHERE email = ?
    """, (email,))

    user = cursor.fetchone()
    conn.close()

    if user is None:
        return None, "User not found"

    user_id, name, stored_hash, role, public_key = user

    # Verify password
    if bcrypt.checkpw(password.encode(), stored_hash.encode()):
        user_data = {
            "id": user_id,
            "name": name,
            "email": email,
            "role": role,
            "ecc_public_key": public_key
        }
        return user_data, "Login successful"
    else:
        return None, "Invalid password"
