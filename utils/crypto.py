import os
import base64
import json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import HTTPException, status

from .config import settings

AES_SECRET_KEY = settings.AES_SECRET_KEY.get_secret_value()

if not AES_SECRET_KEY:
    raise RuntimeError("AES_SECRET_KEY not configured")

AES_SECRET_KEY = base64.b64decode(AES_SECRET_KEY)

if len(AES_SECRET_KEY) != 32:
    raise RuntimeError("AES_SECRET_KEY must be 32 bytes")

def decrypt_payload(encrypted_payload: dict) -> dict:
    try:
        nonce = base64.b64decode(encrypted_payload["nonce"])
        ciphertext = base64.b64decode(encrypted_payload["ciphertext"])

        aesgcm = AESGCM(AES_SECRET_KEY)

        plaintext = aesgcm.decrypt(
            nonce,
            ciphertext,
            None,  # associated_data opcional
        )

        return json.loads(plaintext.decode("utf-8"))

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid encrypted payload",
        )
