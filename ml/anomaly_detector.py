# ml/anomaly_detector.py

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import joblib
import pandas as pd
from datetime import datetime, timedelta
from database.db import get_db_connection
import time

LAST_ANOMALY_TIME = 0
COOLDOWN_SECONDS = 15

BASE_DIR = os.path.dirname(__file__)

model = joblib.load(os.path.join(BASE_DIR, "securecare_isolation_forest.pkl"))
scaler = joblib.load(os.path.join(BASE_DIR, "securecare_scaler.pkl"))



def _extract_features(doctor_id, patient_id, emergency):
    conn = get_db_connection()
    cur = conn.cursor()

    now = datetime.now()
    cur.execute("SELECT datetime('now','localtime','-10 minutes')")
    ten_min_ago = cur.fetchone()[0]


    # 1️⃣ doctor_id
    doc_id = doctor_id

    # 2️⃣ access_count_10min
    cur.execute("""
        SELECT COUNT(*) FROM audit_logs
        WHERE user_id = ?
        AND is_emergency IN (0,1)
        AND timestamp >= ?

    """, (doctor_id, ten_min_ago))
    access_count_10min = cur.fetchone()[0]

    # 3️⃣ unique_patients_10min
    cur.execute("""
       SELECT COUNT(DISTINCT target_id) FROM audit_logs
        WHERE user_id = ?
        AND is_emergency IN (0,1)
        AND timestamp >= ?

    """, (doctor_id, ten_min_ago))
    unique_patients_10min = cur.fetchone()[0]

    # 4️⃣ avg_time_gap_sec
    cur.execute("""
        SELECT timestamp FROM audit_logs
        WHERE user_id = ?
        AND is_emergency IN (0,1)

        ORDER BY timestamp DESC
        LIMIT 2
    """, (doctor_id,))
    rows = cur.fetchall()
    if len(rows) == 2:
        t1 = datetime.fromisoformat(rows[0][0])
        t2 = datetime.fromisoformat(rows[1][0])
        avg_time_gap_sec = abs((t1 - t2).total_seconds())
    else:
        avg_time_gap_sec = 600  # default

    # 5️⃣ hour_of_day
    hour_of_day = now.hour

    # 6️⃣ day_of_week
    day_of_week = now.weekday()

    # 7️⃣ consent_valid_ratio
    cur.execute("""
        SELECT COUNT(*) FROM access_control
        WHERE doctor_id = ?
          AND status = 'active'
          AND consent_end >= CURRENT_TIMESTAMP
    """, (doctor_id,))
    active_consents = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*) FROM access_control
        WHERE doctor_id = ?
    """, (doctor_id,))
    total_consents = cur.fetchone()[0] or 1

    consent_valid_ratio = active_consents / total_consents

    # 8️⃣ session_duration_sec (estimate from audit logs)
    cur.execute("""
        SELECT timestamp FROM audit_logs
            WHERE user_id = ?
            AND is_emergency IN (0,1)

        ORDER BY timestamp ASC
        LIMIT 1
    """, (doctor_id,))
    first = cur.fetchone()
    if first:
        first_time = datetime.fromisoformat(first[0])
        session_duration_sec = (now - first_time).total_seconds()
    else:
        session_duration_sec = 0

    # 9️⃣ is_weekend
    is_weekend = 1 if day_of_week >= 5 else 0

    conn.close()

    features = pd.DataFrame([[
        doc_id,
        access_count_10min,
        unique_patients_10min,
        avg_time_gap_sec,
        hour_of_day,
        day_of_week,
        consent_valid_ratio,
        session_duration_sec,
        is_weekend
    ]], columns=[
        "doctor_id",
        "access_count_10min",
        "unique_patients_10min",
        "avg_time_gap_sec",
        "hour_of_day",
        "day_of_week",
        "consent_valid_ratio",
        "session_duration_sec",
        "is_weekend"
    ])

    return features


def check_anomaly(doctor_id, patient_id, emergency):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT COUNT(*) FROM audit_logs
WHERE user_id = ?
  AND is_emergency IN (0,1)

    """, (doctor_id,))
    total_logs = cur.fetchone()[0]
    conn.close()

    # 🧠 Cold start protection
    if total_logs < 5:
        return False

    global LAST_ANOMALY_TIME

    current_time = time.time()
    if current_time - LAST_ANOMALY_TIME < COOLDOWN_SECONDS:
        return False  # cooldown active

    features = _extract_features(doctor_id, patient_id, emergency)
    scaled = scaler.transform(features)
    pred = model.predict(scaled)

    if pred[0] == -1:
        LAST_ANOMALY_TIME = time.time()
        return True

    return False


