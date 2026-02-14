""" Modelo para almacenar métricas enviadas por agentes """

from __future__ import annotations

from datetime import UTC, datetime
from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from utils.database import Base


class ServerMetrics(Base):
    __tablename__ = "metrics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # Relación con OAuthClient
    client_id: Mapped[int] = mapped_column(
        ForeignKey("clients.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Hostname reportado
    hostname: Mapped[str] = mapped_column(String(150), nullable=False)

    # Timestamp del servidor agente
    server_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    # Considerar un index compuesto (client_id, server_timestamp)
    
    # CPU
    cpu_percent: Mapped[float] = mapped_column(Float, nullable=False)

    # Memoria
    memory_percent: Mapped[float] = mapped_column(Float, nullable=False)

    # Disco
    disk_percent: Mapped[float] = mapped_column(Float, nullable=False)

    # JSON opcional completo (para debug o expansión futura)
    raw_payload: Mapped[dict] = mapped_column(JSON, nullable=True)

    # Timestamp recepción en API
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
