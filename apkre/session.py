"""Per-app analysis session: working directory, SQLite persistence."""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

import sqlalchemy as sa
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session as OrmSession


class Base(DeclarativeBase):
    pass


class EndpointRow(Base):
    __tablename__ = "endpoints"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    method: Mapped[str] = mapped_column(sa.String(16))
    path: Mapped[str] = mapped_column(sa.Text)
    host: Mapped[str] = mapped_column(sa.Text, default="")
    source: Mapped[str] = mapped_column(sa.String(32))
    auth: Mapped[bool] = mapped_column(sa.Boolean, default=False)
    request_body: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    response_body: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    captured_at: Mapped[float] = mapped_column(sa.Float)


class Session:
    """Represents a single analysis session for one APK."""

    def __init__(self, apk_path: str, device: str | None = None) -> None:
        self.apk_path = apk_path
        self.device = device
        self.package_name: str | None = None
        self.tokens: list[str] = []

        apk_name = Path(apk_path).stem
        base = Path.home() / ".apkre" / "sessions"
        base.mkdir(parents=True, exist_ok=True)
        self.work_dir = base / f"{apk_name}_{int(time.time())}"
        self.work_dir.mkdir(parents=True, exist_ok=True)

        db_path = self.work_dir / "session.db"
        self._engine = sa.create_engine(f"sqlite:///{db_path}")
        Base.metadata.create_all(self._engine)

    def save_endpoints(self, endpoints: list[dict], source: str) -> None:
        with OrmSession(self._engine) as s:
            for ep in endpoints:
                row = EndpointRow(
                    method=ep.get("method", "GET").upper(),
                    path=ep.get("path", ""),
                    host=ep.get("host", ""),
                    source=source,
                    auth=bool(ep.get("auth")),
                    request_body=json.dumps(ep["request_body"]) if ep.get("request_body") else None,
                    response_body=json.dumps(ep["response_body"]) if ep.get("response_body") else None,
                    captured_at=time.time(),
                )
                s.add(row)
            s.commit()

    def load_endpoints(self) -> list[dict]:
        with OrmSession(self._engine) as s:
            rows = s.query(EndpointRow).all()
            return [
                {
                    "method": r.method,
                    "path": r.path,
                    "host": r.host,
                    "source": r.source,
                    "auth": r.auth,
                    "request_body": json.loads(r.request_body) if r.request_body else None,
                    "response_body": json.loads(r.response_body) if r.response_body else None,
                }
                for r in rows
            ]
