from apscheduler.schedulers.background import BackgroundScheduler
from .database import SessionLocal
from .security import cleanup_expired_nonces


def start_scheduler():
    """ Ejecutar periodicamente la limpieza de Nounce's """
    scheduler = BackgroundScheduler()

    def job():
        db = SessionLocal()
        try:
            cleanup_expired_nonces(db)
        finally:
            db.close()

    scheduler.add_job(
        job,
        "interval",
        minutes=5,  # cada 5 minutos
        id="nonce_cleanup",
        replace_existing=True,
    )

    scheduler.start()
