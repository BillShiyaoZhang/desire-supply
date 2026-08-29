#!/usr/bin/env python3
"""Create and verify closed Compose inputs for the INTERNAL_SANDBOX stack.

The helper owns only ``compose.env`` and ``compose.ipam.yaml`` inside an
already-created private input root.  It never reads deployment secrets, never
overwrites either output, and reports only a stable non-secret status.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import BinaryIO, NoReturn, Sequence, TextIO


COMPOSE_ENV_NAME = "compose.env"
COMPOSE_IPAM_NAME = "compose.ipam.yaml"
OUTPUT_NAMES = (COMPOSE_ENV_NAME, COMPOSE_IPAM_NAME)
ENV_KEYS = (
    "DESIRE_IMAGE_TAG",
    "DESIRE_DB_PASSWORD_FILE",
    "DESIRE_TAXONOMY_SEED_WORKLOAD_CREDENTIAL_FILE",
    "DESIRE_TAXONOMY_SEED_RECEIPT_HMAC_KEY_FILE",
    "DESIRE_IDENTITY_SOURCE_DIR",
    "DESIRE_INTERNAL_SANDBOX_TLS_DIR",
    "DESIRE_INTERNAL_SANDBOX_BUNDLE_DIR",
)

_SAFE_TOKEN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_SAFE_UNQUOTED_PATH = re.compile(r"^/[A-Za-z0-9._~+/-]+$")
_RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


class InternalSandboxComposeInputError(RuntimeError):
    """Stable, non-reflective Compose input preparation failure."""

    def __init__(self) -> None:
        super().__init__("INTERNAL_SANDBOX_COMPOSE_INPUTS_INVALID")


class _ClosedArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        del message
        _invalid()


def create_compose_inputs(
    input_root: Path,
    *,
    image_tag: str,
    bundle_dir_name: str,
    ingress_subnet: str,
    oidc_subnet: str,
    app_subnet: str,
    data_subnet: str,
) -> None:
    """Exclusive-create the two closed Compose input files."""

    root, documents = _validated_documents(
        input_root,
        image_tag=image_tag,
        bundle_dir_name=bundle_dir_name,
        ingress_subnet=ingress_subnet,
        oidc_subnet=oidc_subnet,
        app_subnet=app_subnet,
        data_subnet=data_subnet,
    )
    targets = tuple(root / name for name in OUTPUT_NAMES)
    if any(path.exists() or path.is_symlink() for path in targets):
        _invalid()

    created: list[tuple[Path, tuple[int, int]]] = []
    try:
        for name in OUTPUT_NAMES:
            target = root / name
            identity = _write_new(target, documents[name], mode=0o600)
            created.append((target, identity))
        verify_compose_inputs(
            root,
            image_tag=image_tag,
            bundle_dir_name=bundle_dir_name,
            ingress_subnet=ingress_subnet,
            oidc_subnet=oidc_subnet,
            app_subnet=app_subnet,
            data_subnet=data_subnet,
        )
    except BaseException:
        for path, identity in reversed(created):
            _unlink_owned(path, identity)
        raise


def verify_compose_inputs(
    input_root: Path,
    *,
    image_tag: str,
    bundle_dir_name: str,
    ingress_subnet: str,
    oidc_subnet: str,
    app_subnet: str,
    data_subnet: str,
) -> None:
    """Verify exact bytes, names, permissions, link count, and file types."""

    root, documents = _validated_documents(
        input_root,
        image_tag=image_tag,
        bundle_dir_name=bundle_dir_name,
        ingress_subnet=ingress_subnet,
        oidc_subnet=oidc_subnet,
        app_subnet=app_subnet,
        data_subnet=data_subnet,
    )
    for name in OUTPUT_NAMES:
        path = root / name
        expected = documents[name]
        if (
            _read_closed_file(path, mode=0o600, expected_size=len(expected))
            != expected
        ):
            _invalid()


def _validated_documents(
    input_root: Path,
    *,
    image_tag: str,
    bundle_dir_name: str,
    ingress_subnet: str,
    oidc_subnet: str,
    app_subnet: str,
    data_subnet: str,
) -> tuple[Path, dict[str, bytes]]:
    root = _root(input_root)
    image = _safe_token(image_tag)
    bundle = _safe_token(bundle_dir_name)
    subnets = _closed_subnets(
        ingress_subnet,
        oidc_subnet,
        app_subnet,
        data_subnet,
    )

    pointers = (
        image,
        _dotenv_path(root / "db_superuser_password.txt"),
        _dotenv_path(root / "taxonomy_seed_workload_credential"),
        _dotenv_path(root / "taxonomy_seed_receipt_hmac_key"),
        _dotenv_path(root / "internal-sandbox-identity-sources"),
        _dotenv_path(root / "internal-sandbox-tls"),
        _dotenv_path(root / bundle),
    )
    if len(ENV_KEYS) != len(pointers):
        _invalid()
    environment = "".join(
        f"{key}={value}\n" for key, value in zip(ENV_KEYS, pointers)
    ).encode("utf-8")
    ingress, oidc, app, data = subnets
    ipam = (
        "networks:\n"
        "  ingress:\n"
        "    ipam:\n"
        "      config:\n"
        f"        - subnet: {ingress}\n"
        "  oidc-backend:\n"
        "    ipam:\n"
        "      config:\n"
        f"        - subnet: {oidc}\n"
        "  app:\n"
        "    ipam:\n"
        "      config:\n"
        f"        - subnet: {app}\n"
        "  data:\n"
        "    ipam:\n"
        "      config:\n"
        f"        - subnet: {data}\n"
    ).encode("ascii")
    return root, {COMPOSE_ENV_NAME: environment, COMPOSE_IPAM_NAME: ipam}


def _root(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        _invalid()
    try:
        root_stat = path.lstat()
    except OSError:
        _invalid()
    if (
        not stat.S_ISDIR(root_stat.st_mode)
        or path.is_symlink()
        or stat.S_IMODE(root_stat.st_mode) != 0o700
    ):
        _invalid()
    return path


def _safe_token(value: str) -> str:
    if not isinstance(value, str) or _SAFE_TOKEN.fullmatch(value) is None:
        _invalid()
    return value


def _dotenv_path(path: Path) -> str:
    value = str(path)
    if any(character in value for character in ("\x00", "\r", "\n")):
        _invalid()
    if _SAFE_UNQUOTED_PATH.fullmatch(value) is not None:
        return value
    if "'" in value or "\\" in value:
        _invalid()
    return f"'{value}'"


def _closed_subnets(*values: str) -> tuple[str, str, str, str]:
    networks: list[ipaddress.IPv4Network] = []
    for value in values:
        if not isinstance(value, str):
            _invalid()
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError:
            _invalid()
        if (
            not isinstance(network, ipaddress.IPv4Network)
            or network.prefixlen != 24
            or not any(network.subnet_of(private) for private in _RFC1918_NETWORKS)
        ):
            _invalid()
        networks.append(network)
    if len(set(networks)) != 4:
        _invalid()
    return (
        str(networks[0]),
        str(networks[1]),
        str(networks[2]),
        str(networks[3]),
    )


def _read_closed_file(path: Path, *, mode: int, expected_size: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        _invalid()
    try:
        file_stat = os.fstat(descriptor)
        try:
            path_stat = path.lstat()
        except OSError:
            _invalid()
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or stat.S_IMODE(file_stat.st_mode) != mode
            or file_stat.st_nlink != 1
            or file_stat.st_size != expected_size
            or path.is_symlink()
            or (file_stat.st_dev, file_stat.st_ino)
            != (path_stat.st_dev, path_stat.st_ino)
        ):
            _invalid()
        chunks: list[bytes] = []
        remaining = expected_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                _invalid()
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            _invalid()
        try:
            final_path_stat = path.lstat()
        except OSError:
            _invalid()
        final_file_stat = os.fstat(descriptor)
        if (
            final_file_stat.st_size != expected_size
            or path.is_symlink()
            or (final_file_stat.st_dev, final_file_stat.st_ino)
            != (final_path_stat.st_dev, final_path_stat.st_ino)
        ):
            _invalid()
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _write_new(path: Path, value: bytes, *, mode: int) -> tuple[int, int]:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, mode)
    identity_stat = os.fstat(descriptor)
    identity = (identity_stat.st_dev, identity_stat.st_ino)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            _write_all(stream, value)
            stream.flush()
            os.fsync(stream.fileno())
        return identity
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        _unlink_owned(path, identity)
        raise


def _unlink_owned(path: Path, identity: tuple[int, int]) -> None:
    try:
        current = path.lstat()
    except OSError:
        return
    if (
        stat.S_ISREG(current.st_mode)
        and not path.is_symlink()
        and (current.st_dev, current.st_ino) == identity
    ):
        try:
            path.unlink()
        except OSError:
            pass


def _write_all(stream: BinaryIO, value: bytes) -> None:
    written = stream.write(value)
    if written != len(value):
        _invalid()


def _invalid() -> NoReturn:
    raise InternalSandboxComposeInputError()


def _add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--input-root", required=True)
    parser.add_argument("--image-tag", required=True)
    parser.add_argument("--bundle-dir-name", required=True)
    parser.add_argument("--ingress-subnet", required=True)
    parser.add_argument("--oidc-subnet", required=True)
    parser.add_argument("--app-subnet", required=True)
    parser.add_argument("--data-subnet", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = _ClosedArgumentParser(
        prog="python3 scripts/prepare_internal_sandbox_compose_inputs.py"
    )
    subcommands = parser.add_subparsers(
        dest="command", required=True, parser_class=_ClosedArgumentParser
    )
    create = subcommands.add_parser("create")
    verify = subcommands.add_parser("verify")
    _add_arguments(create)
    _add_arguments(verify)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    try:
        arguments = _parser().parse_args(argv)
        keyword_arguments = {
            "image_tag": arguments.image_tag,
            "bundle_dir_name": arguments.bundle_dir_name,
            "ingress_subnet": arguments.ingress_subnet,
            "oidc_subnet": arguments.oidc_subnet,
            "app_subnet": arguments.app_subnet,
            "data_subnet": arguments.data_subnet,
        }
        if arguments.command == "create":
            create_compose_inputs(Path(arguments.input_root), **keyword_arguments)
            status = "INTERNAL_SANDBOX_COMPOSE_INPUTS_CREATED"
        else:
            verify_compose_inputs(Path(arguments.input_root), **keyword_arguments)
            status = "INTERNAL_SANDBOX_COMPOSE_INPUTS_VERIFIED"
        stdout.write(json.dumps({"status": status}, separators=(",", ":")) + "\n")
        return 0
    except (InternalSandboxComposeInputError, OSError, TypeError, ValueError):
        stderr.write(
            '{"code":"INTERNAL_SANDBOX_COMPOSE_INPUTS_INVALID",'
            '"status":"BLOCKED"}\n'
        )
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
