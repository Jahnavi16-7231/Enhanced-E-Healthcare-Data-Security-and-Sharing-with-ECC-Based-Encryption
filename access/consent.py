from database.db import get_db_connection
from datetime import datetime, timedelta
from security.audit_logger import log_audit_event
from security.email_notifier import send_emergency_email
def grant_access(patient_id, doctor_id, hours):
    """
    FINAL MODEL:
    - Access control stores ONLY consent metadata
    - NO AES handling
    - NO encryption
    """

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT datetime('now','localtime', ?)", (f"+{hours} hours",))
    expiry = cur.fetchone()[0]

    cur.execute("""
        INSERT INTO access_control
        (patient_id, doctor_id, consent_start, consent_end, status)
        VALUES (?, ?, CURRENT_TIMESTAMP, ?, 'active')
    """, (patient_id, doctor_id, expiry))

    conn.commit()
    conn.close()

    log_audit_event(
        user_id=patient_id,
        action="GRANT_CONSENT",
        target_id=doctor_id
    )
def get_authorized_patients(doctor_id):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT users.id, users.name, users.email
        FROM access_control
        JOIN users ON users.id = access_control.patient_id
        WHERE access_control.doctor_id = ?
          AND access_control.status = 'active'
          AND access_control.consent_end >= CURRENT_TIMESTAMP
    """, (doctor_id,))

    rows = cur.fetchall()
    conn.close()
    return rows


def get_all_doctors():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, name, email
        FROM users
        WHERE role = 'doctor'
    """)

    rows = cur.fetchall()
    conn.close()
    return rows


def has_doctor_access(doctor_id, patient_id):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT 1 FROM access_control
        WHERE doctor_id = ?
          AND patient_id = ?
          AND status = 'active'
          AND consent_end >= CURRENT_TIMESTAMP
    """, (doctor_id, patient_id))

    allowed = cur.fetchone() is not None
    conn.close()
    return allowed
def grant_emergency_access(doctor_id, patient_id, doctor_name, patient_email):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT datetime('now','localtime','+60 minutes')")
    expiry = cur.fetchone()[0]


    cur.execute("""
        INSERT INTO access_control
        (patient_id, doctor_id, consent_start, consent_end, status, is_emergency)
        VALUES (?, ?, CURRENT_TIMESTAMP, ?, 'active', 1)
    """, (patient_id, doctor_id, expiry))

    conn.commit()
    conn.close()

    # 🔐 Audit log
    log_audit_event(
        user_id=doctor_id,
        action="EMERGENCY_ACCESS_GRANTED",
        target_id=patient_id
    )

    # 📧 Email alert
    send_emergency_email(patient_email, doctor_name)