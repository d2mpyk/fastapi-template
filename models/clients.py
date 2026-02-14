""" Modelo OAuthClient para Client Credentials Flow """
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from utils.database import Base


class OAuthClient(Base):
    __tablename__ = "clients"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # Identificador público del cliente (se envía en el request)
    client_id: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )

    # Hash del client_secret (NUNCA guardar el secreto plano)
    client_secret_hash: Mapped[str] = mapped_column(String(255),nullable=False)

    # Nombre descriptivo (ej: agent-server-01)
    name: Mapped[str] = mapped_column(String(100),nullable=False)

    # Rol del cliente (ej: "agent")
    role: Mapped[str] = mapped_column(String(20),nullable=False,default="agent")

    # Scopes futuros (JSON string o CSV simple)
    scopes: Mapped[str | None] = mapped_column(Text,nullable=True,default=None)

    is_active: Mapped[bool] = mapped_column(Boolean,default=True,nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
