#!/usr/bin/env python3
"""Create and verify the closed INTERNAL_SANDBOX TLS fixture.

The root signing key exists only in one OpenSSL child process.  It is streamed
to Python, used through child-process stdin for root and leaf signing, zeroed,
and never written to the output directory or included in a return value.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import NoReturn, Optional, Sequence, TextIO


ROOT_FILE = "root-ca.pem"
CHAIN_FILE = "edge-tls-chain.pem"
KEY_FILE = "edge-tls-key.pem"
EXPECTED_FILES = frozenset((ROOT_FILE, CHAIN_FILE, KEY_FILE))
ROOT_COMMON_NAME = "Desire INTERNAL_SANDBOX Synthetic Root CA v1"
LEAF_COMMON_NAME = "pilot.example.test"
DNS_NAMES = ("identity.example.test", "pilot.example.test")
MINIMUM_REMAINING_SECONDS = 86_400
_ROOT_DAYS = 30
_LEAF_DAYS = 14
_MAX_OPENSSL_OUTPUT = 64 * 1024
_PEM_CERTIFICATE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\r?\n"
    rb"[A-Za-z0-9+/=\r\n]+"
    rb"-----END CERTIFICATE-----\r?\n?"
)


class InternalSandboxTlsError(RuntimeError):
    """Stable non-reflective fixture failure."""

    def __init__(self) -> None:
        super().__init__("INTERNAL_SANDBOX_TLS_INVALID")


def create_fixture(output_dir: Path) -> None:
    """Atomically create the three fixed TLS assets at a new absolute path."""

    temporary: Optional[Path] = None
    root_key = bytearray()
    leaf_key = bytearray()
    try:
        output = _new_target(output_dir)
        openssl = _openssl()
        parent = output.parent
        temporary = Path(tempfile.mkdtemp(prefix=".desire-tls-", dir=str(parent)))
        os.chmod(temporary, 0o700)

        root_key = bytearray(
            _run(
                openssl,
                ("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"),
                maximum=_MAX_OPENSSL_OUTPUT,
            )
        )
        _require_private_key(root_key)
        root_certificate = _run(
            openssl,
            (
                "req",
                "-new",
                "-x509",
                "-sha256",
                "-days",
                str(_ROOT_DAYS),
                "-set_serial",
                "0x" + secrets.token_hex(16),
                "-key",
                "/dev/stdin",
                "-subj",
                "/CN=" + ROOT_COMMON_NAME,
                "-addext",
                "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-addext",
                "subjectKeyIdentifier=hash",
            ),
            stdin=root_key,
            maximum=_MAX_OPENSSL_OUTPUT,
        )

        leaf_key = bytearray(
            _run(
                openssl,
                (
                    "genpkey",
                    "-algorithm",
                    "RSA",
                    "-pkeyopt",
                    "rsa_keygen_bits:2048",
                ),
                maximum=_MAX_OPENSSL_OUTPUT,
            )
        )
        _require_private_key(leaf_key)
        request = _run(
            openssl,
            (
                "req",
                "-new",
                "-sha256",
                "-key",
                "/dev/stdin",
                "-subj",
                "/CN=" + LEAF_COMMON_NAME,
                "-addext",
                "subjectAltName=DNS:" + ",DNS:".join(DNS_NAMES),
            ),
            stdin=leaf_key,
            maximum=_MAX_OPENSSL_OUTPUT,
        )

        root_path = temporary / ROOT_FILE
        request_path = temporary / ".leaf.csr"
        _write_new(root_path, root_certificate, 0o600)
        _write_new(request_path, request, 0o600)
        leaf_certificate = _run(
            openssl,
            (
                "x509",
                "-req",
                "-sha256",
                "-days",
                str(_LEAF_DAYS),
                "-set_serial",
                "0x" + secrets.token_hex(16),
                "-in",
                str(request_path),
                "-CA",
                str(root_path),
                "-CAkey",
                "/dev/stdin",
                "-extfile",
                "/dev/stdin",
            ),
            # One stdin cannot simultaneously contain the signing key and
            # extension configuration.  Use a config file with no secret;
            # the CA key itself is still stdin-only.
            stdin=root_key,
            maximum=_MAX_OPENSSL_OUTPUT,
            extension_text=(
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature,keyEncipherment\n"
                "extendedKeyUsage=serverAuth\n"
                "subjectAltName=DNS:" + ",DNS:".join(DNS_NAMES) + "\n"
                "subjectKeyIdentifier=hash\n"
                "authorityKeyIdentifier=keyid,issuer\n"
            ).encode("ascii"),
            extension_directory=temporary,
        )

        # Remove the non-secret CSR and tighten the final public assets only.
        request_path.unlink()
        _rewrite(root_path, _normalize_pem(root_certificate), 0o444)
        _write_new(
            temporary / CHAIN_FILE,
            _normalize_pem(leaf_certificate) + _normalize_pem(root_certificate),
            0o444,
        )
        _write_new(temporary / KEY_FILE, bytes(leaf_key), 0o400)
        verify_fixture(temporary)
        os.replace(temporary, output)
        temporary = None
    except InternalSandboxTlsError:
        raise
    except BaseException:
        _invalid()
    finally:
        _zero(root_key)
        _zero(leaf_key)
        if temporary is not None:
            shutil.rmtree(temporary, ignore_errors=True)


def verify_fixture(input_dir: Path) -> None:
    """Verify paths, permissions, certificate policy, chain, and leaf key."""

    temporary: Optional[Path] = None
    try:
        directory = _existing_directory(input_dir)
        entries = tuple(directory.iterdir())
        if frozenset(path.name for path in entries) != EXPECTED_FILES:
            _invalid()
        root = _closed_file(directory / ROOT_FILE, mode=0o444, secret=False)
        chain = _closed_file(directory / CHAIN_FILE, mode=0o444, secret=False)
        key = _closed_file(directory / KEY_FILE, mode=0o400, secret=True)
        root_bytes = root.read_bytes()
        chain_bytes = chain.read_bytes()
        key_bytes = key.read_bytes()
        if (
            b"PRIVATE KEY" in root_bytes
            or b"PRIVATE KEY" in chain_bytes
            or b"PRIVATE KEY" not in key_bytes
            or _normalize_pem(root_bytes) != root_bytes
        ):
            _invalid()
        certificates = _PEM_CERTIFICATE.findall(chain_bytes)
        if len(certificates) != 2 or _normalize_pem(certificates[1]) != root_bytes:
            _invalid()

        openssl = _openssl()
        temporary = Path(tempfile.mkdtemp(prefix="desire-tls-verify-"))
        os.chmod(temporary, 0o700)
        leaf = temporary / "leaf.pem"
        _write_new(leaf, _normalize_pem(certificates[0]), 0o600)
        _expect_success(
            openssl,
            ("verify", "-CAfile", str(root), str(leaf)),
        )
        for certificate in (root, leaf):
            _expect_success(
                openssl,
                (
                    "x509",
                    "-checkend",
                    str(MINIMUM_REMAINING_SECONDS),
                    "-noout",
                    "-in",
                    str(certificate),
                ),
            )
        root_text = _text_certificate(openssl, root)
        leaf_text = _text_certificate(openssl, leaf)
        if (
            "Subject: CN=" + ROOT_COMMON_NAME not in root_text
            or "Issuer: CN=" + ROOT_COMMON_NAME not in root_text
            or "CA:TRUE" not in root_text
            or "Certificate Sign" not in root_text
            or "CRL Sign" not in root_text
            or "Subject: CN=" + LEAF_COMMON_NAME not in leaf_text
            or "Issuer: CN=" + ROOT_COMMON_NAME not in leaf_text
            or "CA:FALSE" not in leaf_text
            or "TLS Web Server Authentication" not in leaf_text
            or "Digital Signature" not in leaf_text
            or "Key Encipherment" not in leaf_text
        ):
            _invalid()
        sans = tuple(re.findall(r"DNS:([a-z0-9.-]+)", leaf_text))
        if sans != DNS_NAMES:
            _invalid()
        leaf_public = _run(
            openssl,
            ("x509", "-in", str(leaf), "-pubkey", "-noout"),
            maximum=_MAX_OPENSSL_OUTPUT,
        )
        key_public = _run(
            openssl,
            ("pkey", "-in", str(key), "-pubout"),
            maximum=_MAX_OPENSSL_OUTPUT,
        )
        if not secrets.compare_digest(leaf_public, key_public):
            _invalid()
    except InternalSandboxTlsError:
        raise
    except BaseException:
        _invalid()
    finally:
        if temporary is not None:
            shutil.rmtree(temporary, ignore_errors=True)


def _run(
    openssl: str,
    arguments: Sequence[str],
    *,
    stdin: Optional[bytearray] = None,
    maximum: int,
    extension_text: Optional[bytes] = None,
    extension_directory: Optional[Path] = None,
) -> bytes:
    args = list(arguments)
    extension_path = None
    if extension_text is not None:
        if extension_directory is None:
            _invalid()
        extension_path = extension_directory / ".leaf.ext"
        _write_new(extension_path, extension_text, 0o600)
        try:
            position = args.index("/dev/stdin", args.index("-extfile") + 1)
            args[position] = str(extension_path)
        except (ValueError, IndexError):
            _invalid()
    try:
        completed = subprocess.run(
            [openssl, *args],
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={"LANG": "C", "LC_ALL": "C"},
        )
    finally:
        if extension_path is not None:
            extension_path.unlink(missing_ok=True)
    if (
        completed.returncode != 0
        or not completed.stdout
        or len(completed.stdout) > maximum
        or len(completed.stderr) > maximum
    ):
        _invalid()
    return completed.stdout


def _expect_success(openssl: str, arguments: Sequence[str]) -> None:
    completed = subprocess.run(
        [openssl, *arguments],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        env={"LANG": "C", "LC_ALL": "C"},
    )
    if completed.returncode != 0:
        _invalid()


def _text_certificate(openssl: str, path: Path) -> str:
    raw = _run(
        openssl,
        ("x509", "-in", str(path), "-noout", "-text"),
        maximum=_MAX_OPENSSL_OUTPUT,
    )
    try:
        return raw.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        _invalid()


def _normalize_pem(value: bytes) -> bytes:
    match = _PEM_CERTIFICATE.fullmatch(value.strip() + b"\n")
    if match is None:
        _invalid()
    return match.group(0).replace(b"\r\n", b"\n").rstrip() + b"\n"


def _require_private_key(value: bytearray) -> None:
    if (
        not 1_600 <= len(value) <= 4_096
        or not value.startswith(b"-----BEGIN PRIVATE KEY-----\n")
        or not value.endswith(b"-----END PRIVATE KEY-----\n")
    ):
        _invalid()


def _openssl() -> str:
    value = shutil.which("openssl")
    if not value or not Path(value).is_absolute():
        _invalid()
    return value


def _new_target(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or path.exists() or path.is_symlink():
        _invalid()
    try:
        parent = path.parent.resolve(strict=True)
    except OSError:
        _invalid()
    if path != parent / path.name or not parent.is_dir() or parent.is_symlink():
        _invalid()
    return path


def _existing_directory(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        _invalid()
    resolved = path.resolve(strict=True)
    if (
        resolved != path
        or not resolved.is_dir()
        or resolved.is_symlink()
        or stat.S_IMODE(resolved.stat().st_mode) != 0o700
    ):
        _invalid()
    return resolved


def _closed_file(path: Path, *, mode: int, secret: bool) -> Path:
    if path.is_symlink():
        _invalid()
    resolved = path.resolve(strict=True)
    metadata = resolved.stat()
    maximum = 64 * 1024 if not secret else 16 * 1024
    if (
        resolved != path
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != mode
        or not 1 <= metadata.st_size <= maximum
    ):
        _invalid()
    return resolved


def _write_new(path: Path, value: bytes, mode: int) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        mode,
    )
    try:
        written = 0
        while written < len(value):
            count = os.write(descriptor, value[written:])
            if count <= 0:
                _invalid()
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, mode)


def _rewrite(path: Path, value: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_TRUNC | getattr(os, "O_CLOEXEC", 0))
    try:
        written = 0
        while written < len(value):
            count = os.write(descriptor, value[written:])
            if count <= 0:
                _invalid()
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, mode)


def _zero(value: bytearray) -> None:
    if isinstance(value, bytearray):
        value[:] = b"\0" * len(value)


def _invalid() -> NoReturn:
    raise InternalSandboxTlsError()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="manage_internal_sandbox_tls.py")
    subparsers = parser.add_subparsers(dest="action", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--output-dir", required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--input-dir", required=True)
    return parser


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
) -> int:
    output = sys.stdout if stdout is None else stdout
    errors = sys.stderr if stderr is None else stderr
    arguments = _parser().parse_args(argv)
    try:
        if arguments.action == "create":
            create_fixture(Path(arguments.output_dir))
            output.write('{"status":"INTERNAL_SANDBOX_TLS_CREATED"}\n')
        else:
            verify_fixture(Path(arguments.input_dir))
            output.write('{"status":"INTERNAL_SANDBOX_TLS_VERIFIED"}\n')
        return 0
    except InternalSandboxTlsError:
        errors.write("ERROR: INTERNAL_SANDBOX_TLS_INVALID\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
