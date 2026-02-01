from datetime import UTC, datetime, timedelta
from fastapi import status, HTTPException
import jwt

from pwdlib import PasswordHash
from argon2.exceptions import VerifyMismatchError
from fastapi.security import OAuth2PasswordBearer

from utils.config import settings

# Password Hasher
ph = PasswordHash.recommended()

# Esquema de FastAPI para extraer el token del header "Authorization: Bearer ..."
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/users/token")

def hash_password(password: str) -> str:
    """Genera el hash seguro para guardar en la base de datos."""
    return ph.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica si la contraseña coincide con el hash."""
    try:
        return ph.verify(plain_password, hashed_password)
    except VerifyMismatchError:
        return False

# Crea el token de acceso
def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Genera un JWT firmado"""
    payload = data.copy()
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES.get_secret_value(),
        )
    
    # Authlib requiere claims estándar: 'exp' (expiration) y 'iat' (issued at)
    payload.update({"exp": expire, "iat": datetime.now(UTC)})
     
    # Codificación y firma
    token = jwt.encode(
        payload, 
        settings.SECRET_KEY.get_secret_value(),
        algorithm=settings.ALGORITHM.get_secret_value()
    )
    return token

def verify_access_token(token:str) -> str | None:
    """Verifica un JWT y retorna el 'sub' si es valido."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Error: No se pudieron validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY.get_secret_value(),
            algorithms=[settings.ALGORITHM.get_secret_value()],
            options={"require": ["exp", "iat", "sub"]},
        )
    except jwt.InvalidTokenError:
        return credentials_exception
    else: 
        return payload.get("sub")