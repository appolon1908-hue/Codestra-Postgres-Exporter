#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validate_repository_security", ROOT / "scripts/validate_repository_security.py"
)
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class RepositorySecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sync_source = (ROOT / ".github/workflows/upstream-source-sync.yml").read_text()
        self.sync_document = yaml.safe_load(self.sync_source)

    def test_current_repository_security_contract(self) -> None:
        VALIDATOR.validate_repository()

    def test_mutable_upstream_ref_is_rejected(self) -> None:
        source = json.loads((ROOT / "CODESTRA_UPSTREAM.json").read_text())
        lock = json.loads((ROOT / "CODESTRA_UPSTREAM_LOCK.json").read_text())
        source["upstream_ref"] = "main"
        with self.assertRaisesRegex(ValueError, "upstream_ref_must_be_exact_commit"):
            VALIDATOR.validate_upstream(source, lock)

    def test_exact_pin_bootstrap_allows_only_source_authority_drift(self) -> None:
        source = json.loads((ROOT / "CODESTRA_UPSTREAM.json").read_text())
        lock = json.loads((ROOT / "CODESTRA_UPSTREAM_LOCK.json").read_text())
        source["upstream_ref"] = "b" * 40
        with self.assertRaisesRegex(ValueError, "upstream_lock_not_bound"):
            VALIDATOR.validate_upstream(source, lock)
        VALIDATOR.validate_upstream(
            source, lock, allow_exact_pin_bootstrap=True
        )
        lock["upstream_commit"] = "c" * 40
        with self.assertRaisesRegex(ValueError, "upstream_lock_not_bound"):
            VALIDATOR.validate_upstream(
                source, lock, allow_exact_pin_bootstrap=True
            )

    def test_runtime_least_privilege_contract_fails_closed(self) -> None:
        runtime = json.loads((ROOT / "config/codestra/runtime.v1.json").read_text())
        VALIDATOR.validate_runtime(runtime)
        runtime["databasePolicy"]["superuserAllowed"] = True
        with self.assertRaisesRegex(ValueError, "runtime_database_boundary_drift"):
            VALIDATOR.validate_runtime(runtime)

    def test_sync_uses_reviewed_retry_safe_pull_request(self) -> None:
        VALIDATOR.validate_sync(self.sync_source, self.sync_document)
        unsafe = self.sync_source.replace(
            'git push origin "HEAD:refs/heads/${SYNC_BRANCH}"',
            "git push origin HEAD:main",
        )
        with self.assertRaisesRegex(ValueError, "protected_branch_sync_forbidden"):
            VALIDATOR.validate_sync(unsafe, self.sync_document)
        for token in (
            '[[ "$(git rev-parse "$remote_ref")" == "$REMOTE_SHA" ]]',
            'git rev-parse "${remote_ref}:upstream"',
            'git rev-parse "${remote_ref}:CODESTRA_UPSTREAM_LOCK.json"',
            'git merge-base --is-ancestor "${remote_parent_values[0]}" "$GITHUB_SHA"',
            'git diff --name-only "${remote_parent_values[0]}" "$remote_ref"',
            'LOCAL_SHA="$REMOTE_SHA"',
            "if (( ${#OPEN_PRS[@]} > 1 )); then",
            'export GIT_AUTHOR_DATE="$UPSTREAM_TIMESTAMP"',
        ):
            self.assertIn(token, self.sync_source)
        self.assertNotIn('[[ "$REMOTE_SHA" == "$LOCAL_SHA" ]]', self.sync_source)

    def test_retry_reuses_equivalent_existing_branch_after_main_advances(self) -> None:
        unsafe = self.sync_source.replace('LOCAL_SHA="$REMOTE_SHA"', "true")
        with self.assertRaisesRegex(ValueError, "reviewed_sync_boundary_missing"):
            VALIDATOR.validate_sync(unsafe, yaml.safe_load(unsafe))

    def test_only_the_exact_reviewed_push_form_is_allowed(self) -> None:
        safe = 'git push origin "HEAD:refs/heads/${SYNC_BRANCH}"'
        for command in (
            "git -c remote.origin.push=HEAD:refs/heads/main push origin",
            "git push origin 2>/dev/null HEAD:refs/heads/main",
            "git push origin HEAD:refs/heads/{main,topic}",
            "bash -c 'git push origin HEAD:refs/heads/main'",
        ):
            with self.subTest(command=command):
                unsafe = self.sync_source.replace(safe, command)
                with self.assertRaisesRegex(
                    ValueError, "protected_branch_sync_forbidden:push_not_exact"
                ):
                    VALIDATOR.validate_sync(unsafe, yaml.safe_load(unsafe))

    def test_bot_created_pr_dispatches_exact_branch_validation(self) -> None:
        self.assertEqual(
            self.sync_document["permissions"],
            {"actions": "write", "contents": "write", "pull-requests": "write"},
        )
        self.assertIn(
            'gh workflow run validate.yml --repo "$GITHUB_REPOSITORY" --ref "$SYNC_BRANCH"',
            self.sync_source,
        )

    def test_vendored_tree_is_bound_to_fresh_official_commit(self) -> None:
        source = (ROOT / ".github/workflows/validate.yml").read_text()
        self.assertIn('fetch --depth 1 --no-tags origin "$upstream_ref"', source)
        self.assertIn("rev-parse 'HEAD^{tree}'", source)
        self.assertIn("git rev-parse 'HEAD:upstream'", source)
        self.assertIn('[[ "$vendored_tree" == "$official_tree" ]]', source)

    def test_actions_are_pinned_and_validation_is_unconditional(self) -> None:
        source = (ROOT / ".github/workflows/validate.yml").read_text()
        VALIDATOR.validate_workflow(source)
        unsafe = source.replace("pull_request:\n", "pull_request:\n    paths:\n      - scripts/**\n")
        with self.assertRaisesRegex(ValueError, "pull_request_validation_must_be_unconditional"):
            VALIDATOR.validate_workflow(unsafe)

    def test_repository_tests_are_secret_scanned_and_errors_fail_closed(self) -> None:
        scanner = ROOT / "scripts/reject_repository_secrets.sh"
        VALIDATOR.validate_secret_scanner(scanner.read_text())
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "tests" / "credentials.json"
            fixture.parent.mkdir()
            fixture.write_text(
                "".join(('"client', 'Secret": "actual-sensitive-value"\n'))
            )
            result = subprocess.run(
                [scanner, directory], check=False, capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("secret pattern detected", result.stderr)
            os.symlink(Path(directory) / "missing", Path(directory) / "dangling")
            result = subprocess.run(
                [scanner, directory], check=False, capture_output=True, text=True
            )
            self.assertGreater(result.returncode, 1)
            self.assertIn("symbolic link", result.stderr)

    def test_postgresql_connection_credentials_are_rejected(self) -> None:
        scanner = ROOT / "scripts/reject_repository_secrets.sh"
        fixtures = (
            "postgre" + "sql://monitor:real-password@db.internal/postgres\n",
            "PG" + "PASSWORD=real-password\n",
            '"database_' + 'password": "real-password"\n',
            "DB_" + "PASSWORD=real-password\n",
        )
        with tempfile.TemporaryDirectory() as directory:
            credential = Path(directory) / "config.env"
            for fixture in fixtures:
                with self.subTest(shape=fixture.split("=", 1)[0]):
                    credential.write_text(fixture)
                    result = subprocess.run(
                        [scanner, directory],
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(result.returncode, 1)
                    self.assertIn("secret pattern detected", result.stderr)

    def test_validation_classifies_only_exact_upstream_pin_bootstrap(self) -> None:
        source = (ROOT / ".github/workflows/validate.yml").read_text()
        for token in (
            "Classify an exact upstream-pin bootstrap",
            '(( ${#changed[@]} == 1 ))',
            '[[ "${changed[0]}" == CODESTRA_UPSTREAM.json ]]',
            "validator_args+=(--allow-exact-pin-bootstrap)",
            'validation_ref="$locked_upstream_ref"',
        ):
            self.assertIn(token, source)
        for token in (
            '[[ "$GITHUB_EVENT_NAME" == push ]]',
            'before="${{ github.event.before }}"',
            '(( ${#changed[@]} == 1 ))',
            '[[ "${changed[0]}" == CODESTRA_UPSTREAM.json ]]',
            "validator_args+=(--allow-exact-pin-bootstrap)",
        ):
            self.assertIn(token, self.sync_source)

    def test_whitespace_gate_checks_the_committed_base_to_head_range(self) -> None:
        source = (ROOT / ".github/workflows/validate.yml").read_text()
        self.assertIn("fetch-depth: 0", source)
        self.assertIn('base_sha="${{ github.event.pull_request.base.sha }}"', source)
        self.assertIn(
            'git diff --check "$base_sha" "$GITHUB_SHA" -- . \':(exclude)upstream\'',
            source,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
