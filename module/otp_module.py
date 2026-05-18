import os
import base64
import hashlib


def generate_otp(length: int = None) -> str:
    """
    Generate OTP.
    
    Mode 1 (default): 6 digit numeric OTP untuk key derivation
        generate_otp() → "547355"
    
    Mode 2 (true OTP): sepanjang plaintext untuk XOR layer
        generate_otp(length=100) → Base64 string
    
    Returns: string (6 digit atau Base64)
    """
    if length is None:
        # Mode 1: 6 digit numeric OTP (backward compatibility)
        import secrets
        digits = "0123456789"
        return "".join(secrets.choice(digits) for _ in range(6))
    
    # Mode 2: true OTP sepanjang plaintext
    otp_bytes = os.urandom(length)
    return base64.b64encode(otp_bytes).decode('utf-8')


def otp_xor(data: bytes, otp_b64: str) -> bytes:
    """
    XOR data dengan OTP (One-Time Pad layer).
    
    Sesuai jurnal: C = P XOR K
    """
    otp_bytes = base64.b64decode(otp_b64.encode())
    
    if len(data) != len(otp_bytes):
        raise ValueError(
            f"OTP length ({len(otp_bytes)}) != data length ({len(data)})"
        )
    
    return bytes(a ^ b for a, b in zip(data, otp_bytes))


def generate_otp_aes_key(aes_key: bytes, otp: str) -> bytes:
    """
    Gabungkan AES key dengan 6-digit OTP, lalu hash jadi AES-256 key baru.
    
    Cara lama (backward compat):
        - OTP 6 digit
        - Combined dengan AES key
        - SHA-256 hash
    """
    combined = (
        aes_key +
        str(otp).encode()
    )
    
    return hashlib.sha256(combined).digest()