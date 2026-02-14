import os
import base64
import json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Annotated

from .config import settings
from .database import get_db
from models.security import AESKey

AES_SECRET_KEY = settings.AES_SECRET_KEY.get_secret_value()

if not AES_SECRET_KEY:
    raise RuntimeError("AES_SECRET_KEY not configured")

AES_SECRET_KEY = base64.b64decode(AES_SECRET_KEY)

if len(AES_SECRET_KEY) != 32:
    raise RuntimeError("AES_SECRET_KEY must be 32 bytes")

def decrypt_payload(
        encrypted_payload: dict,
        db: Annotated[Session, Depends(get_db)],
    ) -> dict:
    try:
        key_id = encrypted_payload["key_id"]

        aes_key = db.query(AESKey).filter(
            AESKey.key_id == key_id,
            AESKey.is_active == True,
        ).first()

        if not aes_key:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid key_id",
            )

        secret_key = base64.b64decode(aes_key.key_value)

        nonce = base64.b64decode(encrypted_payload["nonce"])
        ciphertext = base64.b64decode(encrypted_payload["ciphertext"])

        aesgcm = AESGCM(secret_key)

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
