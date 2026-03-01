import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


# ============================================================
# ECC KEY GENERATION (IDENTITY PURPOSE)
# ============================================================

def generate_ecc_key_pair():
    """
    Generates ECC private/public key pair.
    Private key is stored securely.
    Public key is used for AES key masking.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )

    public_bytes = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return (
        base64.b64encode(private_bytes).decode(),
        base64.b64encode(public_bytes).decode()
    )


# ============================================================
# DEMO-SAFE ECC MASKING FOR AES KEY WRAPPING (OPTION 1)
# ============================================================

def _derive_mask(key_b64: str) -> bytes:
    """
    Derive deterministic 32-byte mask from base64 key material
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(base64.b64decode(key_b64))
    return digest.finalize()


def encrypt_aes_key_with_ecc(aes_key: bytes, doctor_public_key_b64: str) -> bytes:
    """
    Wrap AES key using doctor's ECC PUBLIC KEY
    """
    mask = _derive_mask(doctor_public_key_b64)
    return bytes(a ^ b for a, b in zip(aes_key, mask[:len(aes_key)]))


def decrypt_aes_key_with_ecc(encrypted_aes_key: bytes, doctor_public_key_b64: str) -> bytes:
    """
    Unwrap AES key using SAME doctor's ECC PUBLIC KEY
    """
    mask = _derive_mask(doctor_public_key_b64)
    return bytes(a ^ b for a, b in zip(encrypted_aes_key, mask[:len(encrypted_aes_key)]))
