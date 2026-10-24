import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from .config import settings


def now():
    # UTC stored without timezone in SQL for consistent SQLite test and PostgreSQL behavior.
    return datetime.now(timezone.utc).replace(tzinfo=None)


def uid():
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class Source(Base):
    __tablename__ = "sources"
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(30))
    url: Mapped[str] = mapped_column(Text)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_success: Mapped[datetime | None] = mapped_column(DateTime)
    last_attempt: Mapped[datetime | None] = mapped_column(DateTime)
    error: Mapped[str | None] = mapped_column(Text)
    next_run: Mapped[datetime] = mapped_column(DateTime, default=now, index=True)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    data: Mapped[dict] = mapped_column(JSON)
    title: Mapped[str] = mapped_column(Text)
    product: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="unknown", index=True)
    exploited: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now, index=True)


class Alias(Base):
    __tablename__ = "aliases"
    alias: Mapped[str] = mapped_column(String(240), primary_key=True)
    vulnerability_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.id"), index=True)


class SourceRecord(Base):
    __tablename__ = "source_records"
    __table_args__ = (UniqueConstraint("source_id", "source_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    source_id: Mapped[str] = mapped_column(ForeignKey("sources.id"))
    source_key: Mapped[str] = mapped_column(String(240))
    vulnerability_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.id"), index=True)
    data: Mapped[dict] = mapped_column(JSON)
    fingerprint: Mapped[str] = mapped_column(String(64))


class Batch(Base):
    __tablename__ = "batches"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    slot: Mapped[str] = mapped_column(String(40), unique=True)
    cutoff: Mapped[datetime] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    status: Mapped[str] = mapped_column(String(20), default="analyzing", index=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[str | None] = mapped_column(Text)
    coverage: Mapped[list] = mapped_column(JSON, default=list)


class BatchItem(Base):
    __tablename__ = "batch_items"
    __table_args__ = (UniqueConstraint("batch_id", "vulnerability_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    batch_id: Mapped[str] = mapped_column(ForeignKey("batches.id"), index=True)
    vulnerability_id: Mapped[str] = mapped_column(String(36))
    snapshot: Mapped[dict] = mapped_column(JSON)
    priority: Mapped[bool] = mapped_column(Boolean)
    analysis: Mapped[dict | None] = mapped_column(JSON)


class Delivery(Base):
    __tablename__ = "deliveries"
    __table_args__ = (UniqueConstraint("batch_id", "channel", "part"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    batch_id: Mapped[str] = mapped_column(ForeignKey("batches.id"), index=True)
    channel: Mapped[str] = mapped_column(String(16))
    part: Mapped[int] = mapped_column(Integer, default=1)
    payload: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_run: Mapped[datetime] = mapped_column(DateTime, default=now)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime)
    error: Mapped[str | None] = mapped_column(Text)


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    kind: Mapped[str] = mapped_column(String(32))
    source_id: Mapped[str | None] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime)
    error: Mapped[str | None] = mapped_column(Text)


class Audit(Base):
    __tablename__ = "audit"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(DateTime, default=now)
    actor: Mapped[str] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(80))
    target: Mapped[str] = mapped_column(String(200))


class LoginFlow(Base):
    __tablename__ = "login_flows"
    state: Mapped[str] = mapped_column(String(64), primary_key=True)
    verifier: Mapped[str] = mapped_column(String(128))
    nonce: Mapped[str] = mapped_column(String(64))
    expires: Mapped[datetime] = mapped_column(DateTime)


class WebSession(Base):
    __tablename__ = "web_sessions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    subject: Mapped[str] = mapped_column(String(200))
    csrf: Mapped[str] = mapped_column(String(80))
    expires: Mapped[datetime] = mapped_column(DateTime)


class Migration(Base):
    __tablename__ = "schema_migrations"
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    applied: Mapped[datetime] = mapped_column(DateTime, default=now)


class MetadataState(Base):
    __tablename__ = "metadata_state"
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)


class Revision(Base):
    """Immutable facts; canonical linkage can change after a late alias merge."""
    __tablename__ = "vulnerability_revisions"
    __table_args__ = (Index("revision_identity_watermark", "vulnerability_id", "id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id: Mapped[str] = mapped_column(String(36), index=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime)
    published_at: Mapped[datetime | None] = mapped_column(DateTime, index=True)
    important_at: Mapped[datetime | None] = mapped_column(DateTime, index=True)
    content_hash: Mapped[str] = mapped_column(String(64))
    snapshot_bytes: Mapped[int] = mapped_column(Integer)
    snapshot: Mapped[dict] = mapped_column(JSON)


class ReportState(Base):
    __tablename__ = "report_states"
    batch_id: Mapped[str] = mapped_column(ForeignKey("batches.id"), primary_key=True)
    policy: Mapped[int] = mapped_column(Integer, default=5)
    watermark: Mapped[int | None] = mapped_column(Integer)
    cursor: Mapped[int] = mapped_column(Integer, default=0)
    total: Mapped[int] = mapped_column(Integer, default=0)
    new_count: Mapped[int] = mapped_column(Integer, default=0)
    update_count: Mapped[int] = mapped_column(Integer, default=0)
    unknown_count: Mapped[int] = mapped_column(Integer, default=0)
    coverage_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    overview: Mapped[dict] = mapped_column(JSON, default=dict)
    work: Mapped[dict] = mapped_column(JSON, default=dict)


class ReportSelection(Base):
    __tablename__ = "report_selections"
    item_id: Mapped[int] = mapped_column(ForeignKey("batch_items.id"), primary_key=True)
    revision_id: Mapped[int] = mapped_column(ForeignKey("vulnerability_revisions.id"), index=True)
    group_name: Mapped[str] = mapped_column(String(160), index=True)
    rank: Mapped[int] = mapped_column(Integer)
    category: Mapped[str] = mapped_column(String(30))


class UnverifiedItem(Base):
    __tablename__ = "unverified_report_items"
    __table_args__ = (UniqueConstraint("batch_id", "revision_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    batch_id: Mapped[str] = mapped_column(ForeignKey("batches.id"), index=True)
    revision_id: Mapped[int] = mapped_column(ForeignKey("vulnerability_revisions.id"))
    title: Mapped[str] = mapped_column(Text)
    identifiers: Mapped[str] = mapped_column(Text)
    references: Mapped[list] = mapped_column(JSON, default=list)
    date_annotation_id: Mapped[int | None] = mapped_column(ForeignKey("publication_annotations.id"))
    reason: Mapped[str | None] = mapped_column(String(80))


class ReportBacklog(Base):
    """One outstanding, coalesced report candidate per canonical vulnerability."""
    __tablename__ = "report_backlog"
    vulnerability_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    revision_id: Mapped[int] = mapped_column(ForeignKey("vulnerability_revisions.id"), index=True)
    first_eligible_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    category: Mapped[str] = mapped_column(String(30))
    rank: Mapped[int] = mapped_column(Integer)


class ReportCandidate(Base):
    """Small per-batch staging rows: concurrent ingest cannot change the frozen scan."""
    __tablename__ = "report_candidates"
    batch_id: Mapped[str] = mapped_column(ForeignKey("batches.id"), primary_key=True)
    vulnerability_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    revision_id: Mapped[int] = mapped_column(ForeignKey("vulnerability_revisions.id"))
    first_eligible_at: Mapped[datetime] = mapped_column(DateTime)
    category: Mapped[str] = mapped_column(String(30))
    rank: Mapped[int] = mapped_column(Integer)
    date_annotation_id: Mapped[int | None] = mapped_column(ForeignKey("publication_annotations.id"))


class PublicationAnnotation(Base):
    """Append-only date decisions; raw source and historical fact snapshots stay intact."""
    __tablename__ = "publication_annotations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id: Mapped[str] = mapped_column(String(36), index=True)
    policy: Mapped[int] = mapped_column(Integer)
    assessed_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    status: Mapped[str] = mapped_column(String(30), index=True)
    start_at: Mapped[datetime | None] = mapped_column(DateTime, index=True)
    end_at: Mapped[datetime | None] = mapped_column(DateTime)
    fingerprint: Mapped[str] = mapped_column(String(64))
    data: Mapped[dict] = mapped_column(JSON)


class PublicationState(Base):
    __tablename__ = "publication_states"
    vulnerability_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    annotation_id: Mapped[int] = mapped_column(ForeignKey("publication_annotations.id"), index=True)
    policy: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(30), index=True)
    start_at: Mapped[datetime | None] = mapped_column(DateTime, index=True)
    end_at: Mapped[datetime | None] = mapped_column(DateTime)


class RevisionDateProjection(Base):
    __tablename__ = "revision_date_projections"
    revision_id: Mapped[int] = mapped_column(ForeignKey("vulnerability_revisions.id"), primary_key=True)
    policy: Mapped[int] = mapped_column(Integer)
    important_at: Mapped[datetime | None] = mapped_column(DateTime, index=True)
    important_end_at: Mapped[datetime | None] = mapped_column(DateTime)
    timeline: Mapped[dict] = mapped_column(JSON)


class DateEvidenceCache(Base):
    __tablename__ = "date_evidence_cache"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    url: Mapped[str] = mapped_column(Text)
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    retry_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    status: Mapped[str] = mapped_column(String(30))
    data: Mapped[dict] = mapped_column(JSON, default=dict)


def build_engine(url):
    kwargs = {"pool_pre_ping": True}
    if not url.startswith("sqlite"):
        kwargs.update(pool_size=2, max_overflow=0, pool_timeout=15)
    else:
        kwargs["connect_args"] = {"check_same_thread": False}
    return create_engine(url, **kwargs)


_engine = None


def engine():
    global _engine
    if _engine is None:
        _engine = build_engine(settings().database_url.get_secret_value())
    return _engine


def session():
    return sessionmaker(engine(), expire_on_commit=False)()


def migrate():
    # Versioned initial migration. Future releases add explicit numbered transformations.
    with engine().begin() as conn:
        if conn.dialect.name == "postgresql":
            conn.exec_driver_sql("SELECT pg_advisory_xact_lock(86221022)")
        from sqlalchemy import select
        Migration.__table__.create(conn, checkfirst=True)
        versions = set(conn.execute(select(Migration.version)).scalars())
        if versions - {1, 2, 3, 4} or any(v in versions and v - 1 not in versions for v in (2, 3, 4)):
            raise ValueError("数据库迁移版本不兼容，拒绝自动修改")
        if 1 not in versions:
            for table in [Source, Vulnerability, Alias, SourceRecord, Batch, BatchItem, Delivery,
                          Job, Audit, LoginFlow, WebSession]:
                table.__table__.create(conn, checkfirst=True)
            conn.execute(Migration.__table__.insert().values(version=1, applied=now()))
        if 2 not in versions:
            from .migrations import migration_002
            migration_002(conn)
            conn.execute(Migration.__table__.insert().values(version=2, applied=now()))
        if 3 not in versions:
            from .migrations import migration_003
            migration_003(conn)
            conn.execute(Migration.__table__.insert().values(version=3, applied=now()))
        if 4 not in versions:
            from .migrations import migration_004
            migration_004(conn)
            conn.execute(Migration.__table__.insert().values(version=4, applied=now()))
