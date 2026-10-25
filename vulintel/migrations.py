"""Numbered additive migrations. Ledger and advisory locking live in db.migrate()."""


def migration_002(connection):
    """Preserve all legacy tables and archives; add timeline and durable report workflow."""
    from .db import MetadataState, ReportSelection, ReportState, Revision
    for table in [MetadataState, Revision, ReportState, ReportSelection]:
        table.__table__.create(connection, checkfirst=True)
    connection.exec_driver_sql("CREATE TABLE IF NOT EXISTS unverified_report_items ("
                              "id SERIAL PRIMARY KEY, batch_id VARCHAR(36) NOT NULL REFERENCES batches(id), "
                              "revision_id INTEGER NOT NULL REFERENCES vulnerability_revisions(id), "
                              "title TEXT NOT NULL, identifiers TEXT NOT NULL, \"references\" JSON NOT NULL, "
                              "UNIQUE (batch_id, revision_id))" if connection.dialect.name == "postgresql" else
                              "CREATE TABLE IF NOT EXISTS unverified_report_items ("
                              "id INTEGER PRIMARY KEY AUTOINCREMENT, batch_id VARCHAR(36) NOT NULL REFERENCES batches(id), "
                              "revision_id INTEGER NOT NULL REFERENCES vulnerability_revisions(id), "
                              "title TEXT NOT NULL, identifiers TEXT NOT NULL, \"references\" JSON NOT NULL, "
                              "UNIQUE (batch_id, revision_id))")
    connection.exec_driver_sql("CREATE INDEX IF NOT EXISTS ix_unverified_report_items_batch_id "
                               "ON unverified_report_items (batch_id)")


def migration_003(connection):
    """Persistent deferred candidates; existing reports and facts are unchanged."""
    from .db import ReportBacklog
    ReportBacklog.__table__.create(connection, checkfirst=True)
    # Freeze the v3 shape; newer ORM columns reference tables introduced in v4.
    connection.exec_driver_sql("CREATE TABLE IF NOT EXISTS report_candidates ("
                               "batch_id VARCHAR(36) NOT NULL REFERENCES batches(id), "
                               "vulnerability_id VARCHAR(36) NOT NULL, "
                               "revision_id INTEGER NOT NULL REFERENCES vulnerability_revisions(id), "
                               "first_eligible_at TIMESTAMP NOT NULL, category VARCHAR(30) NOT NULL, "
                               "rank INTEGER NOT NULL, PRIMARY KEY (batch_id, vulnerability_id))")


def migration_004(connection):
    from sqlalchemy import inspect
    from .db import DateEvidenceCache, PublicationAnnotation, PublicationState, RevisionDateProjection
    for table in [PublicationAnnotation, PublicationState, RevisionDateProjection, DateEvidenceCache]:
        table.__table__.create(connection, checkfirst=True)
    columns = {column["name"] for column in inspect(connection).get_columns("report_candidates")}
    if "date_annotation_id" not in columns:
        connection.exec_driver_sql("ALTER TABLE report_candidates ADD COLUMN date_annotation_id INTEGER "
                                   "REFERENCES publication_annotations(id)")
    columns = {column["name"] for column in inspect(connection).get_columns("unverified_report_items")}
    if "date_annotation_id" not in columns:
        connection.exec_driver_sql("ALTER TABLE unverified_report_items ADD COLUMN date_annotation_id INTEGER "
                                  "REFERENCES publication_annotations(id)")
    if "reason" not in columns:
        connection.exec_driver_sql("ALTER TABLE unverified_report_items ADD COLUMN reason VARCHAR(80)")


def migration_005(connection):
    from .db import RecentCandidate, RecentSource
    for table in [RecentSource, RecentCandidate]:
        table.__table__.create(connection, checkfirst=True)


def migration_006(connection):
    from .db import Publication, PublicationClaim, PublicationReceipt
    for table in [Publication, PublicationClaim, PublicationReceipt]:
        table.__table__.create(connection, checkfirst=True)
    from sqlalchemy import select, update, delete, literal, or_
    from .db import Batch, ReportState, ReportBacklog, Vulnerability, Job, Audit, now
    for identity, work in connection.execute(select(Batch.id, ReportState.work).join(ReportState).where(
            Batch.status.in_(["preparing", "analyzing", "failed"]))):
        if not work.get("critical_only"):
            connection.execute(update(Batch).where(Batch.id == identity).values(status="superseded", slot="old:" + identity,
                error="1.5.0严重级别策略重建；原分析保留供审计，未计为已报"))
            connection.execute(delete(Job).where(Job.kind == "report", Job.source_id == identity))
            connection.execute(Audit.__table__.insert().values(at=now(), actor="migration-006",
                action="report.policy-superseded", target=identity))
    invalid = select(ReportBacklog.vulnerability_id).outerjoin(Vulnerability,
        Vulnerability.id == ReportBacklog.vulnerability_id).where(or_(Vulnerability.severity != "critical", Vulnerability.id.is_(None)))
    connection.execute(Audit.__table__.insert().from_select(["at", "actor", "action", "target"],
        select(literal(now()), literal("migration-006"), literal("backlog.policy-withdrawn"),
               ReportBacklog.vulnerability_id).where(ReportBacklog.vulnerability_id.in_(invalid))))
    connection.execute(delete(ReportBacklog).where(ReportBacklog.vulnerability_id.in_(invalid)))
