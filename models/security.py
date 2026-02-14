from __future__ import annotations

from datetime import UTC, datetime
from sqlalchemy import (
    DateTime, 
    ForeignKey, 
    Integer, 
    String, 
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from utils.database import Base


class UsedNonce(Base):
    __tablename__ = "used_nonces"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    client_id: Mapped[int] = mapped_column(
        ForeignKey("clients.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    nonce: Mapped[str] = mapped_column(String(100), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    # Considerando un índice único compuesto
    __table_args__ = (
        UniqueConstraint("client_id", "nonce", name="uq_client_nonce"),
    )

class AESKey(Base):
    __tablename__ = "aes_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    key_id: Mapped[str] = mapped_column(String(20), unique=True)

    key_value: Mapped[str] = mapped_column(String(255))  # base64

    is_active: Mapped[bool] = mapped_column(default=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
    )
