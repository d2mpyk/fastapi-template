from sqlalchemy.orm import Session
from models.users import ApprovedUsers
from .database import SessionLocal
from .config import settings


def init_approved_users():
    db = SessionLocal()
    try:
        user = db.query(ApprovedUsers).first()

        if not user:
            ADMIN = settings.ADMIN.get_secret_value()
            new_admin = ApprovedUsers(email=ADMIN)
            db.add(new_admin)
            db.commit()
            db.refresh(new_admin)
    except Exception as e:
        print(f"Error: Inicializando DB: {e}")
    finally:
        db.close()

    