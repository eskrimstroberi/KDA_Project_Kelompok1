import secrets
import hashlib


def generate_otp(length: int = 6) -> str:
    """
    Generate cryptographically secure OTP.
    """

    digits = "0123456789"

    return "".join(
        secrets.choice(digits)
        for _ in range(length)
    )


def generate_otp_aes_key(
    aes_key: bytes,
    otp: str
) -> bytes:
    """
    Gabungkan AES key dengan OTP
    lalu hash menjadi AES-256 key baru.
    """

    combined = (
        aes_key +
        str(otp).encode()
    )

    return hashlib.sha256(combined).digest()