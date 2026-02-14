from datetime import UTC, datetime, timedelta
from fastapi import Depends, HTTPException, status
from fastapi.templating import Jinja2Templates
from typing import Annotated
from sqlalchemy import select
from sqlalchemy.orm import Session
import jwt, smtplib

from pwdlib import PasswordHash
from argon2.exceptions import VerifyMismatchError
from fastapi.security import OAuth2PasswordBearer
from itsdangerous import URLSafeTimedSerializer

from .config import settings
from .database import get_db
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from models.users import User
from models.clients import OAuthClient


# Password Hasher
ph = PasswordHash.recommended()

# Esquema de FastAPI para extraer el token del header "Authorization: Bearer ..."
oauth2_user_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/users/token")
oauth2_client_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/clients/token")

# Configuración de templates
templates = Jinja2Templates(directory="templates")


# ----------------------------------------------------------------------
# HASH el Password
def hash_password(password: str) -> str:
    """Genera el hash seguro para guardar en la base de datos."""
    return ph.hash(password)


# ----------------------------------------------------------------------
# Verifica el Password HASH
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica si la contraseña coincide con el hash."""
    try:
        return ph.verify(plain_password, hashed_password)
    except VerifyMismatchError:
        return False


# ----------------------------------------------------------------------
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
        algorithm=settings.ALGORITHM.get_secret_value(),
    )
    return token


# ----------------------------------------------------------------------
# Verifica el Token de Acceso
def verify_access_token(token: str) -> str | None:
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
            options={"require": ["sub", "exp", "iat"]},
        )
    except (
        jwt.InvalidTokenError | jwt.ExpiredSignatureError | jwt.InvalidAlgorithmError
    ):
        return credentials_exception
    else:
        return payload.get("sub")


# ----------------------------------------------------------------------
# Obtiene el usuario actual
def get_current_user(
    token: Annotated[str, Depends(oauth2_user_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    """Obtiene el usuario actual autenticado."""
    username = verify_access_token(token)
    result = db.execute(select(User).where(User.username == username))
    user = result.scalars().first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token Invalido o Expirado.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Valida si user_id es un entero (Defensa contra JWT manipulados)
    try:
        user_id_int = int(user.id)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token Invalido o Expirado.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    result = db.execute(select(User).where(User.id == user_id_int))
    user = result.scalars().first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario no encontrado.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


# ----------------------------------------------------------------------
# Alias de Modelo
CurrentUser = Annotated[User, Depends(get_current_user)]


# ----------------------------------------------------------------------
# Obtiene el cliente actual
def get_current_client(
    token: str = Depends(oauth2_client_scheme),
    db: Session = Depends(get_db),
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales de autenticación inválidas.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY.get_secret_value(),
            algorithms=[settings.ALGORITHM],
        )

        token_type = payload.get("type")
        client_id = payload.get("sub")

        if token_type != "client" or client_id is None:
            raise credentials_exception

    except (
        jwt.InvalidTokenError | jwt.ExpiredSignatureError | jwt.InvalidAlgorithmError
    ):
        raise credentials_exception

    # Buscar cliente en DB
    result = db.execute(select(OAuthClient).where(OAuthClient.client_id == client_id))
    client = result.scalars().first()

    if client is None or not client.is_active:
        raise credentials_exception

    return client


# ----------------------------------------------------------------------
# Alias de Modelo
CurrentClient = Annotated[OAuthClient, Depends(get_current_user)]


# ----------------------------------------------------------------------
# Crea el token de confirmación de correo
def generate_verification_token(email: str):
    """Genera un token para la verificación del correo"""
    serializer = URLSafeTimedSerializer(
        settings.SECRET_KEY_CHECK_MAIL.get_secret_value()
    )
    return serializer.dumps(
        email, salt=settings.SECURITY_PASSWD_SALT.get_secret_value()
    )


# ----------------------------------------------------------------------
# Verifica el token de confirmación de correo
def confirm_verification_token(token: str, expiration=3600):
    """Verifica un token de confirmación de correo"""
    serializer = URLSafeTimedSerializer(
        settings.SECRET_KEY_CHECK_MAIL.get_secret_value()
    )
    try:
        email = serializer.loads(
            token,
            salt=settings.SECURITY_PASSWD_SALT.get_secret_value(),
            max_age=expiration,  # Token expira en 1 hora
        )
    except Exception:
        return False
    return email


# ----------------------------------------------------------------------
# Envia el email de confirmación
def send_email_confirmation(context: dict):
    """Envia un correo de confirmación de email"""
    email_destinatario = context.get("email")
    DOMINIO = settings.DOMINIO.get_secret_value()
    EMAIL_SERVER = settings.EMAIL_SERVER.get_secret_value()
    EMAIL_PORT = int(settings.EMAIL_PORT.get_secret_value())
    EMAIL_USER = settings.EMAIL_USER.get_secret_value()
    EMAIL_PASSWD = settings.EMAIL_PASSWD.get_secret_value()

    # 1. Obtener y Renderizar la Plantilla
    # Buscamos el archivo y le pasamos el diccionario de contexto completo
    template = templates.get_template("confirmation_tpl.html")
    html_content = template.render(context)

    # 2. Crear el objeto Mensaje (MIMEMultipart es mejor para evitar errores de formato)
    message = MIMEMultipart("alternative")
    message["Subject"] = f"{DOMINIO} - Confirme su correo"
    message["From"] = EMAIL_USER
    message["To"] = email_destinatario

    # 3. Adjuntar el contenido HTML renderizado
    part_html = MIMEText(html_content, "html")
    message.attach(part_html)

    # 4. Enviar
    try:
        with smtplib.SMTP_SSL(EMAIL_SERVER, EMAIL_PORT) as server:
            server.login(EMAIL_USER, EMAIL_PASSWD)
            server.sendmail(EMAIL_USER, email_destinatario, message.as_string())
        print(f"¡Mensaje enviado a {email_destinatario}!")
    except Exception as e:
        print(f"Error enviando email: {e}")
