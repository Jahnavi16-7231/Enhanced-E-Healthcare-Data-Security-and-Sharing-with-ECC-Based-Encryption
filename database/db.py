# database/db.py
# FINAL VERSION – DO NOT MODIFY AGAIN

import sqlite3
from config import DATABASE


def get_db_connection():
    import os
    print("DB ABS PATH:", os.path.abspath(DATABASE))

    conn = sqlite3.connect(
        DATABASE,
        timeout=30,
        check_same_thread=False
    )
    conn.row_factory = sqlite3.Row

    # Enable WAL mode
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")

    return conn

def create_tables():
    conn = get_db_connection()
    cursor = conn.cursor()

    # =====================================================
    # USERS TABLE
    # Stores both patients and doctors
    # =====================================================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('patient', 'doctor')),
            ecc_public_key TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # =====================================================
    # MEDICAL DATA TABLE
    # Stores ONLY encrypted medical files (text/image/pdf)
    # =====================================================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS medical_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            uploader_role TEXT NOT NULL CHECK(uploader_role IN ('patient', 'doctor')),
            encrypted_data BLOB NOT NULL,
            encrypted_aes_key BLOB NOT NULL,
            file_type TEXT NOT NULL,
            doctor_id INTEGER NOT NULL,
            uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_id) REFERENCES users(id),
            FOREIGN KEY (doctor_id) REFERENCES users(id)
)

    """)

    # =====================================================
    # ACCESS CONTROL TABLE
    # Manages patient consent and time-bound doctor access
    # =====================================================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS access_control (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            doctor_id INTEGER NOT NULL,
            consent_start DATETIME NOT NULL,
            consent_end DATETIME NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (patient_id) REFERENCES users(id),
            FOREIGN KEY (doctor_id) REFERENCES users(id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS prescriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            doctor_id INTEGER NOT NULL,
            patient_id INTEGER NOT NULL,
            prescription_text TEXT NOT NULL,
            file_blob BLOB,
            file_type TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )


    """)

    # =====================================================
    # AUDIT LOGS TABLE (FOR FUTURE USE – NO CODE NOW)
    # Tracks all sensitive actions for security proof
    # =====================================================
    # =====================================================
    # AUDIT LOGS TABLE (HASH CHAINED – USED BY ML + SECURITY)
    # =====================================================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            target_id INTEGER,
            timestamp DATETIME DEFAULT (datetime('now','localtime')),
            prev_hash TEXT,
            curr_hash TEXT,
            is_emergency INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)



def get_authorized_records_for_doctor(doctor_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT
        medical_data.id AS record_id,
        medical_data.owner_id AS patient_id,
        medical_data.file_type,
        medical_data.uploaded_at,
        users.name AS patient_name,
        users.email AS patient_email,
        access_control.consent_end
    FROM medical_data
    JOIN users ON users.id = medical_data.owner_id
    LEFT JOIN access_control
        ON access_control.patient_id = medical_data.owner_id
       AND access_control.doctor_id = medical_data.doctor_id
       AND access_control.status = 'active'
    WHERE medical_data.doctor_id = ?
    ORDER BY medical_data.uploaded_at DESC
""", (doctor_id,))



    records = cursor.fetchall()
    conn.close()
    return records


