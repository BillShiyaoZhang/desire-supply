#!/usr/bin/env python3
"""Fail-closed Linux preflight for the opt-in private-server HTTPS bind."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import ipaddress
import json
import re
import subprocess
import sys
from typing import Callable, NoReturn, Optional, Sequence, TextIO


READY = '{"status":"PRIVATE_SERVER_INGRESS_PREFLIGHT_READY"}\n'
BLOCKED = (
    '{"code":"PRIVATE_SERVER_INGRESS_PREFLIGHT_INVALID",'
    '"status":"BLOCKED"}\n'
)
_MAX_COMMAND_OUTPUT = 1024 * 1024
_MAX_INTERFACES = 256
_MAX_ADDRESSES_PER_INTERFACE = 256
_MAX_LISTENERS = 4096
_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_INTERFACE_NAME = re.compile(r"^[A-Za-z0-9_.:@-]{1,64}$")
_LISTENER_STATE = re.compile(r"^[A-Z][A-Z0-9-]{0,31}$")
_BASE_LOOPBACK_BIND = ipaddress.ip_address("127.0.0.1")


class PrivateServerIngressPreflightError(RuntimeError):
    """Stable, non-reflective preflight failure."""

    def __init__(self) -> None:
        super().__init__("PRIVATE_SERVER_INGRESS_PREFLIGHT_INVALID")


@dataclass(frozen=True)
class InterfaceAddress:
    """One address observed on a Linux interface."""

    name: str
    address: str
    is_up: bool
    is_loopback: bool


@dataclass(frozen=True)
class Listener:
    """One local TCP socket fact."""

    local_address: str
    port: int
    state: str


class _ClosedArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        del message
        _invalid()


def validate_private_server_ingress(
    bind_ip: str,
    *,
    interfaces: Sequence[InterfaceAddress],
    listeners: Sequence[Listener],
) -> None:
    """Validate an exact RFC1918 bind against injected, read-only host facts."""

    target = _exact_rfc1918_address(bind_ip)
    if isinstance(interfaces, (str, bytes)) or isinstance(listeners, (str, bytes)):
        _invalid()

    assigned = False
    try:
        interface_count = len(interfaces)
        listener_count = len(listeners)
    except (TypeError, AttributeError):
        _invalid()
    if interface_count > _MAX_INTERFACES or listener_count > _MAX_LISTENERS:
        _invalid()

    for interface in interfaces:
        if not isinstance(interface, InterfaceAddress):
            _invalid()
        if (
            not isinstance(interface.name, str)
            or _INTERFACE_NAME.fullmatch(interface.name) is None
            or type(interface.is_up) is not bool
            or type(interface.is_loopback) is not bool
        ):
            _invalid()
        address = _exact_ip_address(interface.address)
        if (
            address == target
            and interface.is_up
            and not interface.is_loopback
            and not address.is_loopback
        ):
            assigned = True
    if not assigned:
        _invalid()

    for listener in listeners:
        if not isinstance(listener, Listener):
            _invalid()
        if (
            type(listener.port) is not int
            or not 1 <= listener.port <= 65535
            or not isinstance(listener.state, str)
            or _LISTENER_STATE.fullmatch(listener.state) is None
        ):
            _invalid()
        address = _listener_address(listener.local_address)
        if listener.state != "LISTEN" or listener.port != 443:
            continue
        if address == "*":
            _invalid()
        if isinstance(address, ipaddress.IPv4Address):
            if address.is_unspecified or address in (target, _BASE_LOOPBACK_BIND):
                _invalid()
            continue
        mapped = address.ipv4_mapped
        if address.is_unspecified or (
            mapped is not None
            and (
                mapped.is_unspecified
                or mapped in (target, _BASE_LOOPBACK_BIND)
            )
        ):
            _invalid()


def _exact_rfc1918_address(value: str) -> ipaddress.IPv4Address:
    address = _exact_ip_address(value)
    if (
        not isinstance(address, ipaddress.IPv4Address)
        or address.is_unspecified
        or address.is_loopback
        or not any(address in network for network in _RFC1918)
    ):
        _invalid()
    return address


def _exact_ip_address(value: str):
    if not isinstance(value, str) or not value or value != value.strip():
        _invalid()
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        _invalid()
    if str(address) != value:
        _invalid()
    return address


def _listener_address(value: str):
    if not isinstance(value, str) or not value or value != value.strip():
        _invalid()
    if value == "*":
        return value
    candidate = value
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    if "%" in candidate:
        candidate, separator, scope = candidate.partition("%")
        if not separator or _INTERFACE_NAME.fullmatch(scope) is None:
            _invalid()
    return _exact_ip_address(candidate)


def _checked_stdout(result: object) -> str:
    returncode = getattr(result, "returncode", None)
    stdout = getattr(result, "stdout", None)
    stderr = getattr(result, "stderr", None)
    if (
        type(returncode) is not int
        or returncode != 0
        or not isinstance(stdout, str)
        or stderr != ""
        or len(stdout.encode("utf-8")) > _MAX_COMMAND_OUTPUT
        or "\x00" in stdout
    ):
        _invalid()
    return stdout


def _collect_interfaces(command_runner: Callable[[Sequence[str]], object]):
    output = _checked_stdout(
        command_runner(("ip", "-json", "address", "show", "up"))
    )
    try:
        document = json.loads(output)
    except (json.JSONDecodeError, UnicodeError):
        _invalid()
    if not isinstance(document, list) or len(document) > _MAX_INTERFACES:
        _invalid()

    observed = []
    for interface in document:
        if not isinstance(interface, dict):
            _invalid()
        name = interface.get("ifname")
        flags = interface.get("flags")
        address_info = interface.get("addr_info")
        if (
            not isinstance(name, str)
            or _INTERFACE_NAME.fullmatch(name) is None
            or not isinstance(flags, list)
            or len(flags) > 64
            or any(not isinstance(flag, str) for flag in flags)
            or not isinstance(address_info, list)
            or len(address_info) > _MAX_ADDRESSES_PER_INTERFACE
        ):
            _invalid()
        is_up = "UP" in flags
        is_loopback = "LOOPBACK" in flags
        for facts in address_info:
            if not isinstance(facts, dict) or not isinstance(
                facts.get("family"), str
            ):
                _invalid()
            if facts["family"] != "inet":
                continue
            local = facts.get("local")
            if not isinstance(local, str):
                _invalid()
            _exact_ip_address(local)
            observed.append(
                InterfaceAddress(
                    name=name,
                    address=local,
                    is_up=is_up,
                    is_loopback=is_loopback,
                )
            )
    return tuple(observed)


def _collect_listeners(command_runner: Callable[[Sequence[str]], object]):
    output = _checked_stdout(command_runner(("ss", "-H", "-ltn")))
    lines = output.splitlines()
    if len(lines) > _MAX_LISTENERS:
        _invalid()
    listeners = []
    for line in lines:
        if not line or line != line.strip():
            _invalid()
        fields = line.split()
        if (
            len(fields) != 5
            or fields[0] != "LISTEN"
            or not fields[1].isdigit()
            or not fields[2].isdigit()
        ):
            _invalid()
        local_address, local_port = _split_endpoint(fields[3], peer=False)
        _split_endpoint(fields[4], peer=True)
        listeners.append(
            Listener(
                local_address=local_address,
                port=local_port,
                state=fields[0],
            )
        )
    return tuple(listeners)


def _split_endpoint(value: str, *, peer: bool):
    if not isinstance(value, str) or not value or value != value.strip():
        _invalid()
    if value.startswith("["):
        closing = value.find("]")
        if closing <= 1 or value[closing + 1 : closing + 2] != ":":
            _invalid()
        address = value[1:closing]
        port_text = value[closing + 2 :]
    else:
        address, separator, port_text = value.rpartition(":")
        if not separator or not address:
            _invalid()
    _listener_address(address)
    if peer and port_text == "*":
        return address, port_text
    if not port_text.isdigit():
        _invalid()
    port = int(port_text, 10)
    if not 1 <= port <= 65535:
        _invalid()
    return address, port


def _default_command_runner(command: Sequence[str]):
    return subprocess.run(
        list(command),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        timeout=5,
    )


def _invalid() -> NoReturn:
    raise PrivateServerIngressPreflightError()


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    platform_name: Optional[str] = None,
    command_runner: Optional[Callable[[Sequence[str]], object]] = None,
) -> int:
    """Run the Linux-only host collector around the injectable pure validator."""

    parser = _ClosedArgumentParser(add_help=True)
    parser.add_argument("--bind-ip", required=True)
    try:
        arguments = parser.parse_args(argv)
        selected_platform = sys.platform if platform_name is None else platform_name
        if selected_platform != "linux":
            _invalid()
        runner = _default_command_runner if command_runner is None else command_runner
        interfaces = _collect_interfaces(runner)
        listeners = _collect_listeners(runner)
        validate_private_server_ingress(
            arguments.bind_ip,
            interfaces=interfaces,
            listeners=listeners,
        )
    except Exception:
        stderr.write(BLOCKED)
        return 78
    stdout.write(READY)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
