#!/usr/bin/env python3
"""Install the closed real-OIDC egress projection in one network namespace.

The guard receives only reviewed, non-secret IPv4 coordinates.  It never
resolves a hostname and only invokes the local nftables binary.  The nftables
batch is atomic; an API process must not be started in this namespace until
the guard health check succeeds.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
from typing import NoReturn, Sequence


_DB_IPV4_ENV = "DESIRE_REAL_OIDC_DB_DATA_IPV4"
_OIDC_IPV4_ENV = "DESIRE_REAL_OIDC_PINNED_PUBLIC_IPV4"
_PROJECTION_SHA256_ENV = "DESIRE_REAL_OIDC_EGRESS_PROJECTION_SHA256"
_NFT = "/usr/sbin/nft"
_TABLE = "desire_oidc_egress"
_STATE_ROOT = Path("/run/desire-oidc-egress")
_PROJECTION_FILE = _STATE_ROOT / "projection.json"
_DIGEST_FILE = _STATE_ROOT / "projection.sha256"
_RULESET_FILE = _STATE_ROOT / "ruleset.nft"
_RULESET_DIGEST_FILE = _STATE_ROOT / "ruleset.sha256"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


class RealOidcEgressGuardError(RuntimeError):
    """Stable, non-reflective guard failure."""

    def __init__(self) -> None:
        super().__init__("REAL_OIDC_EGRESS_GUARD_INVALID")


def _invalid() -> NoReturn:
    raise RealOidcEgressGuardError()


def _ipv4(value: object, *, public: bool) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or not value.isascii()
    ):
        _invalid()
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        _invalid()
    if not isinstance(address, ipaddress.IPv4Address) or str(address) != value:
        _invalid()
    if public:
        if (
            not address.is_global
            or address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        ):
            _invalid()
    elif (
        not any(address in network for network in _RFC1918)
        or address.is_loopback
        or address.is_multicast
        or address.is_unspecified
    ):
        _invalid()
    return value


def canonical_projection(db_ipv4: object, oidc_ipv4: object) -> bytes:
    """Return the byte-exact, non-secret egress projection descriptor."""

    database = _ipv4(db_ipv4, public=False)
    provider = _ipv4(oidc_ipv4, public=True)
    value = {
        "database": {"ipv4": database, "port": 5432, "verdict": "ALLOW"},
        "dns": {"tcp_port": 53, "udp_port": 53, "verdict": "REJECT"},
        "established_related": "ALLOW",
        "ipv4_other": "REJECT",
        "ipv6": "REJECT",
        "loopback": "ALLOW",
        "oidc": {"ipv4": provider, "port": 443, "verdict": "ALLOW"},
        "output_policy": "DROP",
        "schema": "desire-real-oidc-egress-projection-v1",
    }
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def projection_sha256(db_ipv4: object, oidc_ipv4: object) -> str:
    return hashlib.sha256(canonical_projection(db_ipv4, oidc_ipv4)).hexdigest()


def canonical_rules(db_ipv4: object, oidc_ipv4: object) -> bytes:
    """Render the only atomic nftables ruleset allowed in the namespace."""

    database = _ipv4(db_ipv4, public=False)
    provider = _ipv4(oidc_ipv4, public=True)
    digest = projection_sha256(database, provider)
    return f'''flush ruleset
table inet {_TABLE} {{
    comment "desire-real-oidc-egress-projection-v1:{digest}"
    chain output {{
        type filter hook output priority filter; policy drop;
        udp dport 53 reject comment "dns-udp-reject:{digest}"
        tcp dport 53 reject with tcp reset comment "dns-tcp-reject:{digest}"
        oifname "lo" accept comment "loopback-allow:{digest}"
        ct state established,related accept comment "state-allow:{digest}"
        ip daddr {database} tcp dport 5432 accept comment "database-allow:{digest}"
        ip daddr {provider} tcp dport 443 accept comment "oidc-allow:{digest}"
        meta nfproto ipv6 reject with icmpv6 type admin-prohibited comment "ipv6-reject:{digest}"
        meta nfproto ipv4 reject with icmp type admin-prohibited comment "ipv4-other-reject:{digest}"
        reject comment "other-reject:{digest}"
    }}
}}
'''.encode("ascii")


def _coordinates() -> tuple[str, str, str]:
    database = _ipv4(os.environ.get(_DB_IPV4_ENV), public=False)
    provider = _ipv4(os.environ.get(_OIDC_IPV4_ENV), public=True)
    expected = os.environ.get(_PROJECTION_SHA256_ENV)
    if not isinstance(expected, str) or _SHA256.fullmatch(expected) is None:
        _invalid()
    if projection_sha256(database, provider) != expected:
        _invalid()
    return database, provider, expected


def _nft(arguments: Sequence[str], *, stdin: bytes | None = None) -> bytes:
    if (
        not isinstance(arguments, (tuple, list))
        or not arguments
        or any(not isinstance(value, str) or not value for value in arguments)
        or stdin is not None
        and type(stdin) is not bytes
    ):
        _invalid()
    try:
        result = subprocess.run(
            [_NFT, *arguments],
            input=stdin,
            stdin=subprocess.PIPE if stdin is None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            close_fds=True,
            timeout=5,
            env={
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
            },
        )
    except BaseException:
        _invalid()
    if result.returncode != 0 or type(result.stdout) is not bytes:
        _invalid()
    return result.stdout


def _write_once(path: Path, value: bytes) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
    except OSError:
        _invalid()
    try:
        offset = 0
        while offset < len(value):
            written = os.write(descriptor, value[offset:])
            if written <= 0:
                _invalid()
            offset += written
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_uid != 0
            or metadata.st_nlink != 1
            or metadata.st_size != len(value)
        ):
            _invalid()
    except OSError:
        _invalid()
    finally:
        os.close(descriptor)


def _read_state(path: Path, *, maximum: int) -> bytes:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError:
        _invalid()
    try:
        before = os.fstat(descriptor)
        visible = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o400
            or before.st_uid != 0
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum
            or (before.st_dev, before.st_ino) != (visible.st_dev, visible.st_ino)
        ):
            _invalid()
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                _invalid()
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            _invalid()
        after = os.fstat(descriptor)
        visible_after = path.lstat()
        if (
            (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_uid,
                before.st_nlink,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_uid,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            or (after.st_dev, after.st_ino)
            != (visible_after.st_dev, visible_after.st_ino)
        ):
            _invalid()
        return b"".join(chunks)
    except OSError:
        _invalid()
    finally:
        os.close(descriptor)


def _read_exact(path: Path, expected: bytes) -> None:
    if _read_state(path, maximum=max(1, len(expected))) != expected:
        _invalid()


def _validate_live_ruleset(
    observed: bytes,
    database: str,
    provider: str,
    digest: str,
    *,
    baseline: bytes | None = None,
) -> None:
    if type(observed) is not bytes or not observed or (
        baseline is not None and observed != baseline
    ):
        _invalid()
    expected_markers = (
        f'comment "desire-real-oidc-egress-projection-v1:{digest}"',
        f'comment "dns-udp-reject:{digest}"',
        f'comment "dns-tcp-reject:{digest}"',
        f'comment "loopback-allow:{digest}"',
        f'comment "state-allow:{digest}"',
        f'comment "database-allow:{digest}"',
        f'comment "oidc-allow:{digest}"',
        f'comment "ipv6-reject:{digest}"',
        f'comment "ipv4-other-reject:{digest}"',
        f'comment "other-reject:{digest}"',
    )
    try:
        lines = tuple(
            b" ".join(line.split())
            for line in observed.splitlines()
            if line.strip()
        )
    except BaseException:
        _invalid()
    if (
        len(lines) != 15
        or lines[0] != f"table inet {_TABLE} {{".encode("ascii")
        or lines[1] != expected_markers[0].encode("ascii")
        or lines[2] != b"chain output {"
        or lines[3]
        not in (
            b"type filter hook output priority filter; policy drop;",
            b"type filter hook output priority 0; policy drop;",
        )
        or lines[-2:] != (b"}", b"}")
    ):
        _invalid()
    rule_lines = lines[4:-2]
    rule_markers = expected_markers[1:]
    required_rule_prefixes = (
        b"udp dport 53 reject",
        b"tcp dport 53 reject",
        b'oifname "lo" accept',
        b"ct state",
        f"ip daddr {database} tcp dport 5432 accept".encode("ascii"),
        f"ip daddr {provider} tcp dport 443 accept".encode("ascii"),
        b"meta nfproto ipv6 reject",
        b"meta nfproto ipv4 reject",
        b"reject",
    )
    if len(rule_lines) != len(rule_markers) or any(
        not line.startswith(prefix)
        or not line.endswith(marker.encode("ascii"))
        for line, prefix, marker in zip(
            rule_lines, required_rule_prefixes, rule_markers
        )
    ):
        _invalid()
    if (
        b"established" not in rule_lines[3]
        or b"related" not in rule_lines[3]
        or b"accept" not in rule_lines[3]
        or any(
            observed.count(marker.encode("ascii")) != 1
            for marker in expected_markers
        )
    ):
        _invalid()


def _live_ruleset() -> bytes:
    return _nft(
        (
            "--numeric",
            "--numeric-priority",
            "list",
            "ruleset",
        )
    )


def _verify_live_projection(database: str, provider: str, digest: str) -> None:
    baseline = _read_state(_RULESET_FILE, maximum=64 * 1024)
    _read_exact(
        _RULESET_DIGEST_FILE,
        (hashlib.sha256(baseline).hexdigest() + "\n").encode("ascii"),
    )
    _validate_live_ruleset(
        _live_ruleset(), database, provider, digest, baseline=baseline
    )


def install_projection() -> None:
    database, provider, digest = _coordinates()
    projection = canonical_projection(database, provider)
    rules = canonical_rules(database, provider)
    _nft(("--check", "--file", "-"), stdin=rules)
    _nft(("--file", "-"), stdin=rules)
    baseline = _live_ruleset()
    _validate_live_ruleset(baseline, database, provider, digest)
    _write_once(_PROJECTION_FILE, projection)
    _write_once(_DIGEST_FILE, (digest + "\n").encode("ascii"))
    _write_once(_RULESET_FILE, baseline)
    _write_once(
        _RULESET_DIGEST_FILE,
        (hashlib.sha256(baseline).hexdigest() + "\n").encode("ascii"),
    )
    try:
        directory = os.open(
            _STATE_ROOT,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        os.fsync(directory)
        os.close(directory)
    except OSError:
        _invalid()
    _verify_live_projection(database, provider, digest)


def check_projection() -> None:
    database, provider, digest = _coordinates()
    _read_exact(_PROJECTION_FILE, canonical_projection(database, provider))
    _read_exact(_DIGEST_FILE, (digest + "\n").encode("ascii"))
    _verify_live_projection(database, provider, digest)


def run() -> None:
    install_projection()
    sys.stdout.write('{"status":"REAL_OIDC_EGRESS_GUARD_READY"}\n')
    sys.stdout.flush()
    stopped = False

    def stop(_number: int, _frame: object) -> None:
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not stopped:
        time.sleep(1)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    try:
        if not arguments:
            run()
        elif arguments == ("check",):
            check_projection()
        else:
            _invalid()
    except RealOidcEgressGuardError:
        sys.stderr.write(
            '{"code":"REAL_OIDC_EGRESS_GUARD_INVALID","status":"BLOCKED"}\n'
        )
        return 78
    except BaseException:
        sys.stderr.write(
            '{"code":"REAL_OIDC_EGRESS_GUARD_INVALID","status":"BLOCKED"}\n'
        )
        return 78
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = (
    "RealOidcEgressGuardError",
    "canonical_projection",
    "canonical_rules",
    "check_projection",
    "install_projection",
    "main",
    "projection_sha256",
)
