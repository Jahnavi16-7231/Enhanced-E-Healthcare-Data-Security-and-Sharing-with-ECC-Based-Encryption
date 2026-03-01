import hashlib
from database.db import get_db_connection


def verify_audit_log_chain():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT user_id, action, target_id, timestamp, prev_hash, curr_hash
        FROM audit_logs
        ORDER BY id ASC
    """)
    logs = cur.fetchall()
    conn.close()

    for log in logs:
        expected = hashlib.sha256(
            f"{log['prev_hash']}|{log['user_id']}|{log['action']}|{log['target_id']}|{log['timestamp']}"
            .encode()
        ).hexdigest()

        if expected != log["curr_hash"]:
            return False  # tampering detected

    return True  # logs intact
