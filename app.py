from flask import (
    Flask, render_template, request,
    redirect, url_for, session,
    Response, flash
)

from config import SECRET_KEY
from database.db import (
    create_tables,
    get_db_connection,
    get_authorized_records_for_doctor
)

from auth.register import register_user
from auth.login import login_user
from storage.upload import upload_encrypted_file, allowed_file
from prescription.prescription_service import get_prescriptions_for_doctor, get_prescriptions_for_patient
from access.consent import grant_access, get_all_doctors
from crypto.aes_crypto import aes_decrypt
from crypto.ecc_crypto import decrypt_aes_key_with_ecc
from security.audit_logger import log_audit_event
from access.consent import grant_emergency_access
from ml.anomaly_detector import check_anomaly

app = Flask(__name__)
app.secret_key = SECRET_KEY


# ---------------- HOME ----------------

@app.route("/")
def home():
    return redirect(url_for("login"))


# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user, message = login_user(
            request.form["email"],
            request.form["password"]
        )

        if not user:
            return render_template("login.html", error=message)

        session["user_id"] = user["id"]
        session["user_role"] = user["role"]
        session["user_name"] = user["name"]

        if user["role"] == "doctor":
            return redirect(url_for("doctor_dashboard"))
        else:
            return redirect(url_for("patient_dashboard"))

    return render_template("login.html")


# ---------------- REGISTER ----------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        private_key = register_user(
            request.form["name"],
            request.form["email"],
            request.form["password"],
            request.form["role"]
        )
        return render_template("private_key.html", private_key=private_key)

    return render_template("register.html")


# ---------------- DASHBOARDS ----------------

@app.route("/dashboard/patient")
def patient_dashboard():
    if "user_id" not in session or session["user_role"] != "patient":
        return redirect(url_for("login"))

    doctors = get_all_doctors()
    prescriptions = get_prescriptions_for_patient(session["user_id"])

    return render_template(
        "dashboard_patient.html",
        user={
            "id": session["user_id"],
            "name": session["user_name"]
        },
        doctors=doctors,
        prescriptions=prescriptions
    )

@app.route("/dashboard/doctor")
def doctor_dashboard():
    if "user_id" not in session or session["user_role"] != "doctor":
        return redirect(url_for("login"))
    
    records = get_authorized_records_for_doctor(session["user_id"])
    prescriptions = get_prescriptions_for_doctor(session["user_id"])
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
    SELECT consent_end
    FROM access_control
    WHERE doctor_id = ?
    AND status = 'active'
    AND consent_end >= datetime('now','localtime')
    ORDER BY consent_end DESC
    LIMIT 1
    """, (session["user_id"],))

    row = cur.fetchone()
    conn.close()

    remaining_minutes = 0
    if row:
        from datetime import datetime
        end = datetime.fromisoformat(row["consent_end"])
        remaining_minutes = int((end - datetime.now()).total_seconds() / 60)

    return render_template(
        "dashboard_doctor.html",
        user={
            "id": session["user_id"],
            "name": session["user_name"]
        },
        records=records,
        prescriptions=prescriptions,
        remaining_minutes=remaining_minutes
    )



# ---------------- SECURE FILE UPLOAD ----------------

@app.route("/upload-file", methods=["POST"])
def upload_file():
    if "user_id" not in session or session["user_role"] != "patient":
        return redirect(url_for("login"))

    if "file" not in request.files:
        flash("No file provided.", "danger")
        return redirect(url_for("patient_dashboard"))

    file = request.files["file"]

    if file.filename == "":
        flash("No file selected.", "danger")
        return redirect(url_for("patient_dashboard"))

    if not allowed_file(file.filename):
        flash("Invalid file type.", "danger")
        return redirect(url_for("patient_dashboard"))

    file_bytes = file.read()
    file_type = file.filename.rsplit(".", 1)[1].lower()
    doctor_id = int(request.form["doctor_id"])

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT ecc_public_key FROM users WHERE id = ?",
        (session["user_id"],)
    )
    owner_public_key = cursor.fetchone()["ecc_public_key"]
    conn.close()

    upload_encrypted_file(
        owner_id=session["user_id"],
        uploader_role="patient",
        file_bytes=file_bytes,
        file_type=file_type,
        owner_public_key=owner_public_key,
        doctor_id=doctor_id
    )

    flash("File uploaded and encrypted successfully.", "success")
    return redirect(url_for("patient_dashboard"))


# ---------------- GRANT ACCESS ----------------

@app.route("/grant-access", methods=["POST"])
def grant_access_route():
    if "user_id" not in session or session["user_role"] != "patient":
        return redirect(url_for("login"))

    doctor_id = int(request.form["doctor_id"])
    hours = int(request.form["hours"])

    grant_access(
        patient_id=session["user_id"],
        doctor_id=doctor_id,
        hours=hours
    )

    flash("Doctor access granted successfully.", "success")
    return redirect(url_for("patient_dashboard"))


# ---------------- SECURE VIEW (DELEGATED ACCESS) ----------------

@app.route("/view/<int:record_id>", methods=["POST"])
def view_record(record_id):
    if session.get("user_role") != "doctor":
        return "Unauthorized", 403

    conn = get_db_connection()
    cur = conn.cursor()

    # fetch encrypted file + AES key
    cur.execute("""
        SELECT owner_id, encrypted_data, encrypted_aes_key, file_type
        FROM medical_data
        WHERE id = ?
    """, (record_id,))
    record = cur.fetchone()

    if not record:
        return "Record not found", 404

    # consent check ONLY
    # consent check ONLY
    cur.execute("""
        SELECT 1 FROM access_control
        WHERE doctor_id = ?
        AND patient_id = ?
        AND (
            (status = 'active' AND consent_end >= CURRENT_TIMESTAMP)
            OR
            (is_emergency = 1 AND consent_end >= CURRENT_TIMESTAMP)
        )
    """, (session["user_id"], record["owner_id"]))

    has_access = cur.fetchone() is not None
    log_audit_event(
        user_id=session["user_id"],
        action="VIEW_MEDICAL_RECORD",
        target_id=record_id
    )
    # 🤖 Run ML BEFORE decision
    is_anomaly = check_anomaly(
        doctor_id=session["user_id"],
        patient_id=record["owner_id"],
        emergency=False
    )

    if is_anomaly:
        flash("⚠️ Anomalous access pattern detected!", "danger")

    if not has_access:
        flash("Access denied", "danger")
        return redirect(url_for("doctor_dashboard"))


    # 🔐 FETCH DOCTOR PUBLIC KEY
    cur.execute(
        "SELECT ecc_public_key FROM users WHERE id = ?",
        (session["user_id"],)
    )
    doctor_public_key = cur.fetchone()["ecc_public_key"]

    conn.close()

   
   

    

    # 🔓 Unwrap AES key
    aes_key = decrypt_aes_key_with_ecc(
        record["encrypted_aes_key"],
        doctor_public_key
    )

    plaintext = aes_decrypt(record["encrypted_data"], aes_key)

    return Response(
        plaintext,
        mimetype={
            "pdf": "application/pdf",
            "png": "image/png",
            "jpg": "image/jpeg",
            "jpeg": "image/jpeg"
        }[record["file_type"]]
    )

@app.route("/doctor/add-prescription", methods=["POST"])
def add_prescription_route():
    if session.get("user_role") != "doctor":
        return "Unauthorized", 403

    patient_id = int(request.form["patient_id"])
    text = request.form["prescription_text"]

    file = request.files.get("file")
    file_bytes = file.read() if file else None
    file_type = file.filename.rsplit(".", 1)[1].lower() if file else None

    from prescription.prescription_service import add_prescription
    add_prescription(
        doctor_id=session["user_id"],
        patient_id=patient_id,
        text=text,
        file_bytes=file_bytes,
        file_type=file_type
    )

    flash("Prescription added successfully", "success")
    return redirect(url_for("doctor_dashboard"))
@app.route("/emergency-access", methods=["POST"])
def emergency_access():
    if session.get("user_role") != "doctor":
        return "Unauthorized", 403

    patient_id = int(request.form["patient_id"])

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT email FROM users WHERE id = ?", (patient_id,))
    patient_email = cur.fetchone()["email"]

    cur.execute("SELECT name FROM users WHERE id = ?", (session["user_id"],))
    doctor_name = cur.fetchone()["name"]

    conn.close()

    grant_emergency_access(
        doctor_id=session["user_id"],
        patient_id=patient_id,
        doctor_name=doctor_name,
        patient_email=patient_email
    )
    log_audit_event(
        user_id=session["user_id"],
        action="EMERGENCY_ACCESS",
        target_id=patient_id
    )
    # 🤖 ML Anomaly Detection for emergency
    is_anomaly = check_anomaly(
        doctor_id=session["user_id"],
        patient_id=patient_id,
        emergency=True
    )

    if is_anomaly:
        flash("⚠️ Anomalous EMERGENCY access detected!", "danger")


    flash("🚨 Emergency access granted (patient notified)", "warning")
    return redirect(url_for("doctor_dashboard"))

# ---------------- LOGOUT ----------------

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------- APP START ----------------

if __name__ == "__main__":
    create_tables()
    app.run(debug=True, use_reloader=False, threaded=False)
