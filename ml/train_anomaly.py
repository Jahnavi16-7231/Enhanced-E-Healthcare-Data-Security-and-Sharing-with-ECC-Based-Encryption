import pandas as pd
import numpy as np

from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score
)
from sklearn.preprocessing import StandardScaler

import matplotlib.pyplot as plt
import seaborn as sns
import joblib

# -------------------------------
# 1. Load Dataset
# -------------------------------
df = pd.read_csv("securecare_access_anomaly_dataset.csv")

X = df.drop(columns=["label"])
y = df["label"]  # for evaluation only

# -------------------------------
# 2. Feature Scaling
# -------------------------------
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# -------------------------------
# 3. Train Isolation Forest
# -------------------------------
model = IsolationForest(
    n_estimators=200,
    contamination=0.17,
    random_state=42
)

model.fit(X_scaled)

# -------------------------------
# 4. Predictions
# -------------------------------
y_pred_raw = model.predict(X_scaled)
y_pred = np.where(y_pred_raw == -1, 1, 0)

# -------------------------------
# 5. Evaluation Metrics
# -------------------------------
accuracy = accuracy_score(y, y_pred)

print("\n===== MODEL PERFORMANCE =====")
print(f"Accuracy: {accuracy:.4f}\n")

print("Classification Report:\n")
print(classification_report(y, y_pred, target_names=["Normal", "Anomaly"]))

# -------------------------------
# 6. Confusion Matrix
# -------------------------------
cm = confusion_matrix(y, y_pred)

plt.figure(figsize=(6,4))
sns.heatmap(
    cm,
    annot=True,
    fmt="d",
    cmap="Blues",
    xticklabels=["Normal", "Anomaly"],
    yticklabels=["Normal", "Anomaly"]
)
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.title("Isolation Forest Confusion Matrix")
plt.tight_layout()
plt.show()

# -------------------------------
# 7. Accuracy Bar Chart
# -------------------------------
class_accuracy = {
    "Normal": cm[0,0] / cm[0].sum(),
    "Anomaly": cm[1,1] / cm[1].sum()
}

plt.figure(figsize=(5,4))
plt.bar(class_accuracy.keys(), class_accuracy.values())
plt.ylim(0,1)
plt.ylabel("Accuracy")
plt.title("Class-wise Accuracy")
plt.tight_layout()
plt.show()

# -------------------------------
# 8. Save Model & Scaler
# -------------------------------
joblib.dump(model, "securecare_isolation_forest.pkl")
joblib.dump(scaler, "securecare_scaler.pkl")

print("Model and scaler saved successfully.")
