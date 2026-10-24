"""Identity mappings from structured IDs only; advisory mentions are never aliases."""
import re


CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
DISTRO_CVE_ID = re.compile(r"(?:DEBIAN|UBUNTU)-(CVE-\d{4}-\d{4,})", re.I)


def record_aliases(data):
    values = {str(value).upper() for value in data.get("aliases", [])}
    key = str(data.get("source_key", "")).upper()
    # These database namespaces encode exactly one CVE. Do not regex-search titles,
    # references, descriptions, related IDs or arbitrary advisory names.
    for value in [key, *values]:
        match = DISTRO_CVE_ID.fullmatch(value)
        if match:
            values.add(match[1])
        elif CVE_ID.fullmatch(value):
            values.add(value)
    return sorted(values)


def publication_scope(record):
    # Infer for historical payloads too; a new distro entry is not a new CVE.
    source = record.get("source", "")
    if (source.startswith("osv-") or record.get("source_authority") == "OSV"
            or DISTRO_CVE_ID.fullmatch(str(record.get("source_key", "")))):
        return "source_record"
    if source == "nvd":
        return "record_publication"
    if source == "kev":
        return "kev_added"
    return record.get("publication_scope", "unknown")
