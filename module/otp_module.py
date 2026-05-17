import os
import base64


def generate_otp(length: int = None) -> str:
    """
    Generate TRUE OTP sepanjang plaintext.
    
    Cara 1 (sesuai jurnal): OTP sepanjang data yang akan di-XOR.
    Returns: Base64 string.
    """
    if length is None:
        raise ValueError("Length harus di-set! OTP harus sepanjang plaintext.")
    
    otp_bytes = os.urandom(length)
    return base64.b64encode(otp_bytes).decode('utf-8')


def otp_xor(data: bytes, otp_b64: str) -> bytes:
    """
    XOR data dengan OTP (One-Time Pad layer).
    
    Sesuai jurnal: C = P XOR K
    """
    otp_bytes = base64.b64decode(otp_b64.encode())
    
    if len(data) != len(otp_bytes):
        raise ValueError(f"OTP length ({len(otp_bytes)}) != data length ({len(data)})")
    
    return bytes(a ^ b for a, b in zip(data, otp_bytes))


def generate_otp_aes_key(aes_key: bytes, otp: str) -> bytes:
    """
    Cara 1: OTP nggak dipakai untuk derive AES key.
    AES key tetap pure. Function ini di-keep untuk backward compat.
    """
    # Kalo Cara 1, OTP nggak modify AES key
    return aes_key