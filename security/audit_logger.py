import hashlib
from database.db import get_db_connection

GENESIS_HASH = "0" * 64  # initial hash


def _get_last_hash():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT curr_hash
        FROM audit_logs
        ORDER BY id DESC
        LIMIT 1
    """)
    row = cur.fetchone()
    conn.close()

    return row["curr_hash"] if row else GENESIS_HASH


def _generate_hash(prev_hash, user_id, action, target_id, timestamp):
    data = f"{prev_hash}|{user_id}|{action}|{target_id}|{timestamp}"
    return hashlib.sha256(data.encode()).hexdigest()


def log_audit_event(user_id, action, target_id=None):
    conn = get_db_connection()
    cur = conn.cursor()

    prev_hash = _get_last_hash()

    # ✅ Correct local timestamp
    cur.execute("SELECT datetime('now','localtime')")
    timestamp = cur.fetchone()[0]

    curr_hash = _generate_hash(
        prev_hash,
        user_id,
        action,
        target_id,
        timestamp
    )

    # ✅ Decide ML relevance
    is_emergency = 2
    if action in ["VIEW_MEDICAL_RECORD", "UPLOAD_MEDICAL_RECORD", "EMERGENCY_ACCESS"]:
        is_emergency = 1 if action == "EMERGENCY_ACCESS" else 0

    # ✅ Proper insert
    cur.execute("""
        INSERT INTO audit_logs
        (user_id, action, target_id, timestamp, prev_hash, curr_hash, is_emergency)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        action,
        target_id,
        timestamp,
        prev_hash,
        curr_hash,
        is_emergency
    ))

    conn.commit()
    conn.close()
