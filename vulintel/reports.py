"""Archive paths and export primitives shared by the durable report renderer."""
from .config import settings

LABELS = {"vulnerability_summary": "漏洞说明", "root_cause": "原理", "trigger_conditions": "触发前提", "impact": "影响",
          "affected_versions": "影响版本", "attack_path": "攻击路径", "remediation": "修复与缓解",
          "evidence_level": "证据等级", "evidence_notes": "证据说明"}


def report_dir(batch_id):
    # Only DB-generated UUIDs are accepted, not user paths.
    import uuid
    return settings().data_dir / "reports" / str(uuid.UUID(batch_id))


def export_item(item):
    return {"item_id": item.id, "priority": item.priority,
            "facts": item.snapshot, "analysis": item.analysis}


def csv_safe(value):
    value = str(value or "")
    return "'" + value if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else value
