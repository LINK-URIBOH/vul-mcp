"""Numbered additive migrations. Ledger and advisory locking live in db.migrate()."""


def migration_002(connection):
    """Preserve all legacy tables and archives; add timeline and durable report workflow."""
    from .db import MetadataState, ReportSelection, ReportState, Revision, UnverifiedItem
    for table in [MetadataState, Revision, ReportState, ReportSelection, UnverifiedItem]:
        table.__table__.create(connection, checkfirst=True)
