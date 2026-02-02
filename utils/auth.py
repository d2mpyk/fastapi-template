from datetime import UTC, datetime, timedelta
from fastapi import status, HTTPException
import jwt, smtplib

from pwdlib import PasswordHash
from argon2.exceptions import VerifyMismatchError
from fastapi.security import OAuth2PasswordBearer
from itsdangerous import URLSafeTimedSerializer

from email.mime.text import MIMEText

from .config import settings
from .auxiliars import confirmation

# Password Hasher
ph = PasswordHash.recommended()

# Esquema de FastAPI para extraer el token del header "Authorization: Bearer ..."
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/users/token")

# HASH el Password
def hash_password(password: str) -> str:
    """Genera el hash seguro para guardar en la base de datos."""
    return ph.hash(password)

# Verifica el Password HASH
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

# Verifica el Token de Acceso
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
            options={"require": ["sub", "exp", "iat"]},
        )
    except jwt.InvalidTokenError | jwt.ExpiredSignatureError | jwt.InvalidAlgorithmError:
        return credentials_exception
    else: 
        return payload.get("sub")

# Crea el token de confirmación de correo
def generate_verification_token(email: str):
    serializer = URLSafeTimedSerializer(settings.SECRET_KEY_CHECK_MAIL.get_secret_value())
    return serializer.dumps(email, salt=settings.SECURITY_PASSWD_SALT.get_secret_value())

# Verifica el token de confirmación de correo
def confirm_verification_token(token: str, expiration=3600):
    serializer = URLSafeTimedSerializer(settings.SECRET_KEY_CHECK_MAIL.get_secret_value())
    try:
        email = serializer.loads(
            token,
            salt=settings.SECURITY_PASSWD_SALT.get_secret_value(),
            max_age=expiration # Token expira en 1 hora
        )
    except Exception:
        return False
    return email

# Envia el email de confirmación
def send_email(email: str, url: str):
    DOMINIO = settings.DOMINIO.get_secret_value()
    EMAIL_SERVER = settings.EMAIL_SERVER.get_secret_value()
    EMAIL_PORT = int(settings.EMAIL_PORT.get_secret_value())
    EMAIL_USER = settings.EMAIL_USER.get_secret_value()
    EMAIL_PASSWD = settings.EMAIL_PASSWD.get_secret_value()
    # Creación del Body
    body = format(f"{confirmation}",url)
    # Cree un objeto MIMEText con el cuerpo del email.
    msg = MIMEText(body)
    # Establezca el asunto del email.
    msg['Subject'] = f"{DOMINIO} - Confirme su correo"
    # Establezca el email del remitente.
    msg['From'] = EMAIL_USER
    # Una la lista de destinatarios en una sola string separada por comas.
    msg['To'] = ', '.join(email)
   
    # Conecte al servidor SMTP de Gmail usando SSL.
    with smtplib.SMTP_SSL(EMAIL_SERVER, EMAIL_PORT) as smtp_server:
        # Inicie sesión en el servidor SMTP usando las credenciales del remitente.
        smtp_server.login(EMAIL_USER, EMAIL_PASSWD)
        # Envíe el email. La función sendmail requiere el email del remitente, la lista de destinatarios y el mensaje de email como string.
        smtp_server.sendmail(EMAIL_USER, email, msg.as_string())
    # Imprima un mensaje en consola después de enviar exitosamente el email.
    print("¡Mensaje enviado!")