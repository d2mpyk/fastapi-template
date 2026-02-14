from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from typing import Annotated
from datetime import datetime

from utils.database import get_db
from utils.auth import get_current_client
from utils.crypto import decrypt_payload
from models.clients import OAuthClient
from models.metrics import ServerMetrics
from models.security import UsedNonce

from dateutil.parser import isoparse

router = APIRouter()


# ----------------------------------------------------------------------
#  Endpoint protegido solo para OAuth Clients (agents)
@router.post(
    "",
    status_code=status.HTTP_200_OK,
)
def receive_metrics(
    encrypted_payload: dict,
    db: Annotated[Session, Depends(get_db)],
    current_client: OAuthClient = Depends(get_current_client),
):
    """ Endpoint protegido solo para OAuth Clients (agents) """

    # Validar rol
    if current_client.role != "agent":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permiso Denegado",
        )

    # Validación anti-Replay
    nonce_value = encrypted_payload.get("nonce")

    if not nonce_value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nonce missing",
        )

    new_nonce = UsedNonce(
        client_id=current_client.id,
        nonce=nonce_value,
    )

    try:
        db.add(new_nonce)
        db.commit()
        db.refresh(new_nonce)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Replay attack detected",
        )

    # 🔓 Descifrar
    decrypted_data = decrypt_payload(encrypted_payload)

    # Aquí puedes validar estructura mínima
    if "system" not in decrypted_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid metrics format",
        )
    
    try:
        hostname = decrypted_data["system"]["hostname"]
        server_timestamp = isoparse(decrypted_data["system"]["timestamp"])

        cpu_percent = decrypted_data["cpu"]["cpu_percent"]
        memory_percent = decrypted_data["memory"]["percent"]
        disk_percent = decrypted_data["disk"]["percent"]

    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid metrics structure",
        )

    # 💾 Guardar en DB
    new_metrics = ServerMetrics(
        client_id=current_client.id,
        hostname=hostname,
        server_timestamp=server_timestamp,
        cpu_percent=cpu_percent,
        memory_percent=memory_percent,
        disk_percent=disk_percent,
        raw_payload=decrypted_data,
    )

    db.add(new_metrics)
    db.commit()
    db.refresh(new_metrics)

    return {
        "message": "Metrics stored successfully",
        "client": current_client.client_id,
    }
