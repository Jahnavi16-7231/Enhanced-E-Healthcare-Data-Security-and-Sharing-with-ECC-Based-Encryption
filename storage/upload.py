from crypto.aes_crypto import aes_encrypt
from crypto.ecc_crypto import encrypt_aes_key_with_ecc
from database.db import get_db_connection

from security.audit_logger import log_audit_event



# ------------------------------------------------
# File validation
# ------------------------------------------------

ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ------------------------------------------------
# Secure upload (FINAL ARCHITECTURE)
# ------------------------------------------------

def upload_encrypted_file(
    owner_id,
    uploader_role,
    file_bytes,
    file_type,
    owner_public_key,   # kept for compatibility (not used)
    doctor_id
):
    # AES encrypt file
    encrypted_data, aes_key, iv = aes_encrypt(file_bytes)

    conn = get_db_connection()
    cursor = conn.cursor()

    # 🔐 Fetch DOCTOR ECC public key
    cursor.execute(
        "SELECT ecc_public_key FROM users WHERE id = ?",
        (doctor_id,)
    )
    doctor_public_key = cursor.fetchone()["ecc_public_key"]

    # 🔐 Wrap AES key using DOCTOR public key
    encrypted_aes_key = encrypt_aes_key_with_ecc(
        aes_key,
        doctor_public_key
    )

    # Store encrypted file + encrypted AES key
    cursor.execute("""
        INSERT INTO medical_data
        (owner_id, uploader_role, encrypted_data, encrypted_aes_key, file_type, doctor_id, uploaded_at)
        VALUES (?, ?, ?, ?, ?, ?, datetime('now','localtime'))
    """, (

        owner_id,
        uploader_role,
        iv+encrypted_data ,
        encrypted_aes_key,
        file_type,
        doctor_id
    ))
    record_id = int(cursor.lastrowid)
    conn.commit()
    conn.close()
    log_audit_event(
    user_id=owner_id,
    action="UPLOAD_MEDICAL_RECORD",
    target_id=record_id
)