from typing import Annotated
from datetime import timedelta
import secrets

from fastapi import APIRouter, Depends, Form, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import select

from models.clients import OAuthClient
from schemas.clients import (
    ClientCreate,
    ClientCreateResponse,
    ClientTokenResponse,
)
from utils.database import get_db
from utils.auth import hash_password, create_access_token, verify_password
from utils.config import settings
from routers.users import get_current_admin
from models.users import User


router = APIRouter()


# ----------------------------------------------------------------------
# Crea un Client (solo admin)
@router.post(
    "/create",
    response_model=ClientCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_oauth_client(
    client_data: ClientCreate,
    db: Annotated[Session, Depends(get_db)],
    admin_user: Annotated[User, Depends(get_current_admin)],
):
    """Crea un Client (solo admin)"""

    # 1️⃣ Generar credenciales seguras
    client_id = secrets.token_urlsafe(32)
    client_secret = secrets.token_urlsafe(48)

    # 2️⃣ Hash del secret (Argon2)
    client_secret_hash = hash_password(client_secret)

    # 3️⃣ Crear instancia
    new_client = OAuthClient(
        client_id=client_id,
        client_secret_hash=client_secret_hash,
        name=client_data.name,
        role=client_data.role,
        scopes=client_data.scopes,
        is_active=True,
    )

    db.add(new_client)
    db.commit()
    db.refresh(new_client)

    # 4️⃣ Responder mostrando secret SOLO UNA VEZ
    return ClientCreateResponse(
        id=new_client.id,
        client_id=new_client.client_id,
        client_secret=client_secret,
        name=new_client.name,
        role=new_client.role,
        scopes=new_client.scopes,
        is_active=new_client.is_active,
        created_at=new_client.created_at,
    )


# ----------------------------------------------------------------------
# OAuth2 Client Credentials Flow
@router.post(
    "/token",
    response_model=ClientTokenResponse,
    status_code=status.HTTP_200_OK,
)
def client_credentials_token(
    db: Annotated[Session, Depends(get_db)],
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
):
    """OAuth2 Client Credentials Flow"""

    # 1️⃣ Validar grant_type
    if grant_type != "client_credentials":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported grant_type",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 2️⃣ Buscar cliente
    result = db.execute(select(OAuthClient).where(OAuthClient.client_id == client_id))
    client = result.scalars().first()

    # 3️⃣ Verificar si existe y Verificar secret (Argon2)
    if not client or not verify_password(client_secret, client.client_secret_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales de cliente Inválidas",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 4️⃣ Verificar si está activo
    if not client.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Error: Cliente inactivo",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 5️⃣ Definir expiración
    access_token_expires = timedelta(
        minutes=int(settings.ACCESS_TOKEN_EXPIRE_MINUTES.get_secret_value())
    )

    # 6️⃣ Crear JWT
    access_token = create_access_token(
        data={
            "sub": str(client.client_id),
            "type": "client",
            "role": str(client.role),
        },
        expires_delta=access_token_expires,
    )

    return ClientTokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=access_token_expires,
    )
