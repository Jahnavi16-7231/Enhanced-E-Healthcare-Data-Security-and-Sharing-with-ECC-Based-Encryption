Enhanced E-Healthcare Data Security and Sharing

A secure and patient-centric e-healthcare data management system that protects sensitive medical data using hybrid cryptography and consent-based access control.
Overview
SecureCare addresses the critical security challenges in modern healthcare by combining AES encryption, Elliptic Curve Cryptography (ECC), and intelligent access control mechanisms to ensure that patient medical data remains confidential, integrity-preserved, and accessible only to authorized personnel.
Features

🔐 AES Encryption — Medical records encrypted at rest using Advanced Encryption Standard
🔑 ECC Key Management — AES keys secured using Elliptic Curve Cryptography
✅ Consent-Based Access Control — Patients grant temporary, revocable access to doctors
🛡️ Attribute-Based Access Control (ABAC) — Fine-grained authorization based on role, consent status, and context
📋 Secure Prescription Management — Doctors can issue prescriptions; patients can view but not modify
📜 Tamper-Evident Audit Logging — All actions logged with cryptographic hash chaining
🚨 Anomaly Detection — Rule-based and ML-based detection of suspicious access patterns
🆘 Emergency Break-Glass Access — Time-limited emergency access with full logging and patient notification

Tech Stack

Backend: Python, Flask
Database: SQLite
Cryptography: AES (symmetric), ECC (asymmetric), Hybrid encryption model

Security Architecture
The system uses a hybrid cryptographic model where patient medical records are encrypted using AES, and the AES encryption keys are further secured using ECC public keys. Decryption happens in-memory only, ensuring no plaintext data is ever stored on the server.


<img width="588" height="345" alt="image" src="https://github.com/user-attachments/assets/c68a281e-50f3-4c7f-84a4-775c3b2d0045" />




Getting Started
bash# Clone the repository
git clone https://github.com/yourusername/securecare.git

# Navigate to project directory
cd securecare

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
Research Paper
This system is based on the research paper "Secure Care: A Patient-Centric E-Healthcare Data Management System Using Hybrid Cryptography and Consent-Based Access Control".
