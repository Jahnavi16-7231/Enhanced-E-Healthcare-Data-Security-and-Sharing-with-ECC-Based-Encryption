import pandas as pd
import random

random.seed(42)

NORMAL_SAMPLES = 200
ANOMALY_SAMPLES = 40

rows = []

# -------- NORMAL BEHAVIOR --------
for _ in range(NORMAL_SAMPLES):
    rows.append({
        "doctor_id": random.randint(1, 10),
        "access_count_10min": random.randint(1, 4),
        "unique_patients_10min": random.randint(1, 2),
        "avg_time_gap_sec": random.randint(180, 600),
        "hour_of_day": random.randint(9, 17),
        "day_of_week": random.randint(0, 4),
        "consent_valid_ratio": round(random.uniform(0.9, 1.0), 2),
        "session_duration_sec": random.randint(600, 1200),
        "is_weekend": 0,
        "label": 0
    })

# -------- ANOMALOUS BEHAVIOR --------
for _ in range(ANOMALY_SAMPLES):
    rows.append({
        "doctor_id": random.randint(1, 10),
        "access_count_10min": random.randint(10, 25),
        "unique_patients_10min": random.randint(5, 12),
        "avg_time_gap_sec": random.randint(5, 40),
        "hour_of_day": random.choice([0,1,2,3,22,23]),
        "day_of_week": random.randint(5, 6),
        "consent_valid_ratio": round(random.uniform(0.0, 0.6), 2),
        "session_duration_sec": random.randint(120, 300),
        "is_weekend": 1,
        "label": 1
    })

df = pd.DataFrame(rows)
df = df.sample(frac=1).reset_index(drop=True)

df.to_csv("securecare_access_anomaly_dataset.csv", index=False)

print("Dataset generated successfully!")
print("Total rows:", len(df))
print("Normal samples:", NORMAL_SAMPLES)
print("Anomaly samples:", ANOMALY_SAMPLES)
