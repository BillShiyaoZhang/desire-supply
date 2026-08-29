#!/usr/bin/env python3
"""Create and verify the local-only INTERNAL_SANDBOX deployment inputs.

The command intentionally owns only the four deployment secrets and the twenty
closed fictional identity source files which precede TLS and runtime-bundle
generation.  It never overwrites a path and never prints secret material.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import sys
from typing import BinaryIO, NoReturn, Sequence, TextIO


SECRET_FILES = {
    "db_superuser_password.txt": (32, 256, False),
    "taxonomy_seed_workload_credential": (32, 256, False),
    "taxonomy_seed_receipt_hmac_key": (32, 32, True),
    "oidc-client-secret": (32, 4096, False),
}
IDENTITY_DIRECTORY = "internal-sandbox-identity-sources"
IDENTITY_FILES = {
    "access_admin_01.subject": b"sandbox:access-admin-01",
    "access_admin_01.email": b"sandbox-access-admin-01@example.test",
    "appeal_reviewer_01.subject": b"sandbox:appeal-reviewer-01",
    "appeal_reviewer_01.email": b"sandbox-appeal-reviewer-01@example.test",
    "creator_01.subject": b"sandbox:creator-01",
    "creator_01.email": b"sandbox-creator-01@example.test",
    "demand_owner_01.subject": b"sandbox:demand-owner-01",
    "demand_owner_01.email": b"sandbox-demand-owner-01@example.test",
    "finance_operator_01.subject": b"sandbox:finance-operator-01",
    "finance_operator_01.email": (
        b"sandbox-finance-operator-01@example.test"
    ),
    "finance_operator_02.subject": b"sandbox:finance-operator-02",
    "finance_operator_02.email": (
        b"sandbox-finance-operator-02@example.test"
    ),
    "operations_reviewer_01.subject": b"sandbox:operations-reviewer-01",
    "operations_reviewer_01.email": (
        b"sandbox-operations-reviewer-01@example.test"
    ),
    "org_admin_01.subject": b"sandbox:org-admin-01",
    "org_admin_01.email": b"sandbox-org-admin-01@example.test",
    "trust_officer_01.subject": b"sandbox:trust-officer-01",
    "trust_officer_01.email": b"sandbox-trust-officer-01@example.test",
    "trust_officer_02.subject": b"sandbox:trust-officer-02",
    "trust_officer_02.email": b"sandbox-trust-officer-02@example.test",
}


class InternalSandboxInputError(RuntimeError):
    """Stable, non-reflective input preparation failure."""

    def __init__(self) -> None:
        super().__init__("INTERNAL_SANDBOX_INPUTS_INVALID")


def create_inputs(output_root: Path) -> None:
    """Create all closed inputs under an existing absolute directory."""

    root = _root(output_root)
    identity_root = root / IDENTITY_DIRECTORY
    targets = tuple(root / name for name in SECRET_FILES) + (identity_root,)
    if any(path.exists() or path.is_symlink() for path in targets):
        _invalid()

    generated = {
        "db_superuser_password.txt": secrets.token_urlsafe(48).encode("ascii"),
        "taxonomy_seed_workload_credential": secrets.token_urlsafe(48).encode(
            "ascii"
        ),
        "taxonomy_seed_receipt_hmac_key": secrets.token_bytes(32),
        "oidc-client-secret": secrets.token_urlsafe(48).encode("ascii"),
    }
    if len({hashlib.sha256(value).digest() for value in generated.values()}) != len(
        generated
    ):
        _invalid()

    created_files: list[Path] = []
    created_identity = False
    try:
        for name, value in generated.items():
            target = root / name
            _write_new(target, value, 0o600)
            created_files.append(target)
        identity_root.mkdir(mode=0o755)
        created_identity = True
        for name, value in IDENTITY_FILES.items():
            target = identity_root / name
            _write_new(target, value, 0o444)
            created_files.append(target)
        verify_inputs(root)
    except BaseException:
        for path in reversed(created_files):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        if created_identity:
            try:
                identity_root.rmdir()
            except OSError:
                pass
        raise


def verify_inputs(output_root: Path) -> None:
    """Verify names, permissions, shapes, uniqueness, and fictional identities."""

    root = _root(output_root)
    secret_values: list[bytes] = []
    for name, (minimum, maximum, binary) in SECRET_FILES.items():
        path = _closed_file(root / name, mode=0o600)
        value = path.read_bytes()
        if not minimum <= len(value) <= maximum:
            _invalid()
        if not binary:
            try:
                decoded = value.decode("ascii")
            except UnicodeDecodeError:
                _invalid()
            if not decoded.isprintable() or any(char in decoded for char in "\r\n\x00"):
                _invalid()
        secret_values.append(value)
    if len({hashlib.sha256(value).digest() for value in secret_values}) != len(
        secret_values
    ):
        _invalid()

    identity_root = root / IDENTITY_DIRECTORY
    if (
        not identity_root.is_dir()
        or identity_root.is_symlink()
        or stat.S_IMODE(identity_root.stat().st_mode) != 0o755
        or {path.name for path in identity_root.iterdir()} != set(IDENTITY_FILES)
    ):
        _invalid()
    for name, expected in IDENTITY_FILES.items():
        path = _closed_file(identity_root / name, mode=0o444)
        if path.read_bytes() != expected:
            _invalid()


def _root(path: Path) -> Path:
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        _invalid()
    return path


def _closed_file(path: Path, *, mode: int) -> Path:
    try:
        file_stat = path.lstat()
    except OSError:
        _invalid()
    if (
        not stat.S_ISREG(file_stat.st_mode)
        or stat.S_IMODE(file_stat.st_mode) != mode
        or path.is_symlink()
        or file_stat.st_nlink != 1
    ):
        _invalid()
    return path


def _write_new(path: Path, value: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            _write_all(stream, value)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _write_all(stream: BinaryIO, value: bytes) -> None:
    written = stream.write(value)
    if written != len(value):
        _invalid()


def _invalid() -> NoReturn:
    raise InternalSandboxInputError()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 scripts/prepare_internal_sandbox_inputs.py"
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    create = subcommands.add_parser("create")
    create.add_argument("--output-root", required=True)
    verify = subcommands.add_parser("verify")
    verify.add_argument("--input-root", required=True)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    try:
        arguments = _parser().parse_args(argv)
        if arguments.command == "create":
            create_inputs(Path(arguments.output_root))
            status = "INTERNAL_SANDBOX_INPUTS_CREATED"
        else:
            verify_inputs(Path(arguments.input_root))
            status = "INTERNAL_SANDBOX_INPUTS_VERIFIED"
        stdout.write(json.dumps({"status": status}, separators=(",", ":")) + "\n")
        return 0
    except (InternalSandboxInputError, OSError):
        stderr.write(
            '{"code":"INTERNAL_SANDBOX_INPUTS_INVALID","status":"BLOCKED"}\n'
        )
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
