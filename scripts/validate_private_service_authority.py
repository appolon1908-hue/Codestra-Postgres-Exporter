#!/usr/bin/env python3
"""Fail closed if PostgreSQL Exporter is assigned a public hostname or route."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "config" / "private-service-authority.v1.json"
FORBIDDEN_HOST = "pgex" + ".codestra.media"
PRIVATE_IDENTITY = "postgres-exporter:9187"


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_policy() -> dict[str, Any]:
    try:
        value = json.loads(POLICY.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"invalid private-service authority JSON: {exc}")
    if not isinstance(value, dict):
        fail("private-service authority root must be an object")
    return value


def validate_policy() -> None:
    policy = load_policy()
    if policy.get("schema_version") != "1.0":
        fail("schema_version must be 1.0")
    if policy.get("status") != "ACTIVE_SOURCE_AUTHORITY":
        fail("private-service authority must be active")
    if policy.get("repository_id") != 1350839865:
        fail("stable repository ID is incorrect")
    if policy.get("repository") != "appolon1908-hue/Codestra-Postgres-Exporter":
        fail("principal repository is incorrect")
    if policy.get("public_hostname") is not None:
        fail("PostgreSQL Exporter may not have a public hostname")
    if policy.get("private_service_identity") != PRIVATE_IDENTITY:
        fail("private service identity must be postgres-exporter:9187")
    if policy.get("exposure") != "PRIVATE_INTERNAL_ONLY":
        fail("exposure must remain private/internal only")
    if policy.get("routine_consumer") != (
        "Prometheus on an approved private monitoring network"
    ):
        fail("routine consumer policy is incorrect")
    if policy.get("forbidden_public_hostname") != FORBIDDEN_HOST:
        fail("retired public hostname must remain explicitly forbidden")
    for gate in (
        "caddy_publication_allowed",
        "kong_publication_allowed",
        "host_public_port_allowed",
    ):
        if policy.get(gate) is not False:
            fail(f"{gate} must be false")
    controls = policy.get("required_controls")
    if not isinstance(controls, list) or len(controls) < 8:
        fail("required private-service controls are incomplete")


def validate_active_source() -> None:
    allowed_literal_paths = {POLICY.resolve()}
    ignored_parts = {".git", "upstream"}
    ignored_suffixes = {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".woff",
        ".woff2",
        ".zip",
        ".gz",
    }
    public_route_markers = (
        "reverse_proxy postgres-exporter",
        "upstream postgres-exporter",
        "host_port: 9187",
        "0.0.0.0:9187",
        "[::]:9187",
    )

    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if ignored_parts.intersection(path.parts):
            continue
        if path.suffix.lower() in ignored_suffixes:
            continue
        if path.resolve() in allowed_literal_paths:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if FORBIDDEN_HOST in text:
            fail(
                "retired public hostname remains in active source: "
                f"{path.relative_to(ROOT)}"
            )
        lowered = text.lower()
        for marker in public_route_markers:
            if marker in lowered:
                fail(
                    "possible public PostgreSQL Exporter exposure marker "
                    f"{marker!r} in {path.relative_to(ROOT)}"
                )


def main() -> None:
    validate_policy()
    validate_active_source()
    print("PostgreSQL Exporter private-service authority: PASS")


if __name__ == "__main__":
    main()
