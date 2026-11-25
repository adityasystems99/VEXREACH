"""OpenVEX 0.2.0 structural validator ensuring standards compliance."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from packages.core.models.openvex import (
    OpenVEXDocument,
    VEXJustification,
    VEXStatus,
)

OPENVEX_020_CONTEXT = "https://openvex.dev/ns/v0.2.0"
_VALID_STATUSES = {s.value for s in VEXStatus}
_VALID_JUSTIFICATIONS = {j.value for j in VEXJustification}


def validate_openvex_json_payload(payload: dict[str, Any]) -> tuple[bool, list[str]]:
    """Validate a raw JSON-LD dictionary against OpenVEX 0.2.0 core structural rules."""
    errors: list[str] = []

    if payload.get("@context") != OPENVEX_020_CONTEXT:
        errors.append(f"@context must equal '{OPENVEX_020_CONTEXT}'.")

    doc_id = payload.get("@id")
    if not isinstance(doc_id, str) or not doc_id.strip():
        errors.append("@id must be a non-empty IRI string.")

    for req in ("author", "timestamp", "version"):
        if req not in payload or payload[req] is None:
            errors.append(f"Missing required OpenVEX field '{req}'.")

    ts = payload.get("timestamp")
    if isinstance(ts, str):
        try:
            datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            errors.append(f"Invalid ISO-8601 timestamp '{ts}'.")

    ver = payload.get("version")
    if not isinstance(ver, int) or ver < 1:
        errors.append("OpenVEX 'version' must be a positive integer >= 1.")

    statements = payload.get("statements")
    if not isinstance(statements, list):
        errors.append("OpenVEX 'statements' must be a list.")
        return False, errors

    for idx, stmt in enumerate(statements):
        if not isinstance(stmt, dict):
            errors.append(f"statements[{idx}] must be an object.")
            continue
        vuln = stmt.get("vulnerability")
        if not isinstance(vuln, dict) or not (vuln.get("name") or vuln.get("@id")):
            errors.append(f"statements[{idx}].vulnerability must contain 'name' or '@id'.")

        products = stmt.get("products")
        if not isinstance(products, list) or len(products) == 0:
            errors.append(f"statements[{idx}].products must be a non-empty list.")

        status = stmt.get("status")
        if status not in _VALID_STATUSES:
            errors.append(
                f"statements[{idx}].status '{status}' is not in {sorted(_VALID_STATUSES)}."
            )
            continue

        just = stmt.get("justification")
        impact = stmt.get("impact_statement")
        if status == VEXStatus.NOT_AFFECTED.value:
            has_just = just in _VALID_JUSTIFICATIONS
            has_impact = isinstance(impact, str) and bool(impact.strip())
            if just is not None and just not in _VALID_JUSTIFICATIONS:
                errors.append(f"statements[{idx}].justification '{just}' is invalid.")
            if not (has_just or has_impact):
                errors.append(
                    f"statements[{idx}] with status 'not_affected' requires valid 'justification' or 'impact_statement'."
                )
        elif just is not None:
            errors.append(
                f"statements[{idx}] must not specify 'justification' when status is '{status}'."
            )

    return len(errors) == 0, errors


def validate_openvex_document(doc: OpenVEXDocument) -> tuple[bool, list[str]]:
    """Serialize an :class:`OpenVEXDocument` to JSON-LD and validate its OpenVEX 0.2.0 schema."""
    payload = json.loads(doc.to_openvex_json())
    return validate_openvex_json_payload(payload)
