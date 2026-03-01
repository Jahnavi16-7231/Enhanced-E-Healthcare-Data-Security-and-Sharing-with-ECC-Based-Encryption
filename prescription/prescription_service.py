from database.db import get_db_connection
from security.audit_logger import log_audit_event
from security.email_notifier import send_emergency_email


def add_prescription(doctor_id, patient_id, text, file_bytes=None, file_type=None):
    """
    Doctor adds a prescription for a patient
    """
    conn = get_db_connection()
    cur = conn.cursor()

    # Insert prescription
    cur.execute("""
        INSERT INTO prescriptions
        (doctor_id, patient_id, prescription_text, file_blob, file_type)
        VALUES (?, ?, ?, ?, ?)
    """, (doctor_id, patient_id, text, file_bytes, file_type))

    conn.commit()

    # 📧 Notify patient (correct mail type)
    cur.execute("SELECT email FROM users WHERE id = ?", (patient_id,))
    patient_email = cur.fetchone()[0]

    cur.execute("SELECT name FROM users WHERE id = ?", (doctor_id,))
    doctor_name = cur.fetchone()[0]

    send_emergency_email(
        patient_email,
        doctor_name,
        mode="prescription"   # important
    )

    conn.close()

    # 🔒 Audit log
    log_audit_event(
        user_id=doctor_id,
        action="ADD_PRESCRIPTION",
        target_id=patient_id
    )


def get_prescriptions_for_doctor(doctor_id):
    """
    Fetch all prescriptions written by this doctor
    """
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT 
            p.id,
            p.patient_id,
            u.name AS patient_name,
            p.prescription_text,
            p.file_type,
            p.created_at
        FROM prescriptions p
        JOIN users u ON u.id = p.patient_id
        WHERE p.doctor_id = ?
        ORDER BY p.created_at DESC
    """, (doctor_id,))

    rows = cur.fetchall()
    conn.close()
    return rows


def get_prescriptions_for_patient(patient_id):
    """
    Fetch prescriptions received by patient
    """
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            p.prescription_text,
            p.file_type,
            p.created_at,
            u.name AS doctor_name
        FROM prescriptions p
        JOIN users u ON u.id = p.doctor_id
        WHERE p.patient_id = ?
        ORDER BY p.created_at DESC
    """, (patient_id,))

    rows = cur.fetchall()
    conn.close()
    return rows
