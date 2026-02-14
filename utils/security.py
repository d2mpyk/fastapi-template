from datetime import datetime, timedelta, UTC
from sqlalchemy.orm import Session

from models.security import UsedNonce
from .config import settings


def cleanup_expired_nonces(db: Session):
    """ Elimina los Nounces que tengan mas de NONCE_TTL_MINUTES """
    expiration_time = datetime.now(UTC) - timedelta(
        minutes=int(settings.NONCE_TTL_MINUTES.get_secret_value())
    )

    db.query(UsedNonce).filter(
        UsedNonce.created_at < expiration_time
    ).delete(synchronize_session=False)

    db.commit()
