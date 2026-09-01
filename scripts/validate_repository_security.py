#!/usr/bin/env python3
"""Validate Codestra PostgreSQL Exporter protected source authority."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
def validate_upstream(source: dict, lock: dict) -> None:
    expected = {
        "component": "PostgreSQL Exporter",
        "codestra_repository": "appolon1908-hue/Codestra-Postgres-Exporter",
        "upstream_repository": "prometheus-community/postgres_exporter",
        "upstream_clone_url": "https://github.com/prometheus-community/postgres_exporter.git",
        "import_path": "upstream",
        "deployment_enabled": False,
        "secret_material_allowed_in_git": False,
    }
    for key, value in expected.items():
        if source.get(key) != value:
            raise ValueError(f"upstream_authority_drift:{key}")
    ref = source.get("upstream_ref")
    if not isinstance(ref, str) or re.fullmatch(r"[0-9a-f]{40}", ref) is None:
        raise ValueError("upstream_ref_must_be_exact_commit")
    for key in (
        "upstream_clone_url",
        "import_path",
        "deployment_enabled",
        "secret_material_allowed_in_git",
    ):
        if lock.get(key) != expected[key]:
            raise ValueError(f"upstream_lock_drift:{key}")
    if lock.get("upstream_ref") != ref or lock.get("upstream_commit") != ref:
        raise ValueError("upstream_lock_not_bound_to_exact_ref")


def validate_runtime(runtime: dict) -> None:
    expected = {
        "service": "postgres-exporter",
        "component": "PostgreSQL Exporter",
        "repository": "appolon1908-hue/Codestra-Postgres-Exporter",
        "internalEndpoint": "http://postgres-exporter:9187/metrics",
        "hostPortPublished": False,
        "publicHostnameAssigned": False,
        "publicNativePortAllowed": False,
    }
    for key, value in expected.items():
        if runtime.get(key) != value:
            raise ValueError(f"runtime_authority_drift:{key}")
    if runtime.get("networks") != {
        "observability": "codestra-observability",
        "database": "codestra-database",
        "internetIngressAllowed": False,
    }:
        raise ValueError("runtime_network_boundary_drift")
    credentials = runtime.get("credentials") or {}
    if credentials.get("secretMaterialAllowedInGit") is not False:
        raise ValueError("runtime_secret_boundary_drift")
    database = runtime.get("databasePolicy") or {}
    for key in ("superuserAllowed", "databaseOwnerAllowed", "applicationWriteAllowed"):
        if database.get(key) is not False:
            raise ValueError(f"runtime_database_boundary_drift:{key}")
    if database.get("dedicatedMonitoringIdentityRequired") is not True:
        raise ValueError("runtime_monitoring_identity_not_required")
    prometheus = runtime.get("prometheus") or {}
    if prometheus.get("targetActivation") != "pending":
        raise ValueError("runtime_prometheus_activation_drift")
    activation = runtime.get("activation") or {}
    if activation.get("deploymentEnabled") is not False or activation.get("productionApproved") is not False:
        raise ValueError("runtime_deployment_must_remain_disabled")


def validate_sync(source: str, document: dict) -> None:
    if (document.get("permissions") or {}) != {
        "actions": "write",
        "contents": "write",
        "pull-requests": "write",
    }:
        raise ValueError("sync_permissions_drift")
    forbidden = (
        r"git\s+push\s+origin\s+(?:HEAD:)?(?:main|staging|production)(?:\s|$)",
        r"git\s+push\s+--force",
    )
    if any(re.search(pattern, source) for pattern in forbidden):
        raise ValueError("protected_branch_sync_forbidden")
    required = (
        "[[ \"$UPSTREAM_REF\" =~ ^[0-9a-f]{40}$ ]]",
        "[[ \"$UPSTREAM_SHA\" == \"$UPSTREAM_REF\" ]]",
        'SYNC_BRANCH="sync/postgres-exporter-upstream-${UPSTREAM_SHA}"',
        'git read-tree --prefix=upstream/ "${UPSTREAM_SHA}^{tree}"',
        '[[ "$REMOTE_SHA" == "$LOCAL_SHA" ]]',
        "gh pr list",
        "Multiple open synchronization pull requests found.",
        "gh pr create",
        "--base main",
        'gh workflow run validate.yml --repo "$GITHUB_REPOSITORY" --ref "$SYNC_BRANCH"',
        "'synchronized_at': os.environ['UPSTREAM_TIMESTAMP']",
        'export GIT_AUTHOR_DATE="$UPSTREAM_TIMESTAMP"',
        'export GIT_COMMITTER_DATE="$UPSTREAM_TIMESTAMP"',
        "Validate Codestra runtime contract",
        "validate_repository_security.py",
    )
    for token in required:
        if token not in source:
            raise ValueError(f"reviewed_sync_boundary_missing:{token}")


def validate_workflow(source: str) -> None:
    required = (
        "pull_request:",
        "workflow_dispatch:",
        "validate-source:",
        "name: validate-source",
        "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
        "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
        "persist-credentials: false",
        "fetch-depth: 0",
        "Bind vendored Git tree to exact official commit",
        "git rev-parse 'HEAD:upstream'",
        '[[ "$vendored_tree" == "$official_tree" ]]',
        'git diff --check "$base_sha" "$GITHUB_SHA" -- . \':(exclude)upstream\'',
    )
    for token in required:
        if token not in source:
            raise ValueError(f"validation_boundary_missing:{token}")
    if re.search(r"uses:\s+actions/(?:checkout|setup-python)@v\d+", source):
        raise ValueError("mutable_action_reference")
    if re.search(r"pull_request:\s*\n\s+paths:", source):
        raise ValueError("pull_request_validation_must_be_unconditional")
    if re.search(r"^\s*git diff --check\s*$", source, re.MULTILINE):
        raise ValueError("whitespace_check_must_use_committed_range")


def validate_repository() -> None:
    paths = {
        "source": ROOT / "CODESTRA_UPSTREAM.json",
        "lock": ROOT / "CODESTRA_UPSTREAM_LOCK.json",
        "sync": ROOT / ".github/workflows/upstream-source-sync.yml",
        "validate": ROOT / ".github/workflows/validate.yml",
        "runtime": ROOT / "config/codestra/runtime.v1.json",
    }
    for path in paths.values():
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"required_regular_file_missing:{path.relative_to(ROOT)}")
    source = json.loads(paths["source"].read_text())
    lock = json.loads(paths["lock"].read_text())
    runtime = json.loads(paths["runtime"].read_text())
    sync_source = paths["sync"].read_text()
    validate_source = paths["validate"].read_text()
    validate_upstream(source, lock)
    validate_runtime(runtime)
    validate_sync(sync_source, yaml.safe_load(sync_source))
    yaml.safe_load(validate_source)
    validate_workflow(validate_source)
    if (ROOT / "upstream/.git").exists():
        raise ValueError("nested_upstream_git_metadata_forbidden")


if __name__ == "__main__":
    try:
        validate_repository()
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as error:
        raise SystemExit(f"POSTGRES_EXPORTER_SOURCE_SECURITY=FAIL ERROR={error}") from error
    print("POSTGRES_EXPORTER_SOURCE_SECURITY=PASS")
    print("UPSTREAM_COMMIT_PINNED=YES")
    print("RUNTIME_CONTRACT=PASS")
    print("SYNC_THROUGH_REVIEWED_PR=YES")
    print("DEPLOYMENT_ENABLED=NO")
