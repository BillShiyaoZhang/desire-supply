"""DNS-free HTTPS transport for one reviewed public OIDC endpoint address."""

from __future__ import annotations

from http.client import HTTPException, HTTPSConnection
import ipaddress
import json
import re
import socket
import ssl
from typing import Any, Mapping
from urllib.parse import urlencode, urlsplit


_DNS_NAME = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\Z"
)


class PinnedPublicIpOidcJsonTransport:
    """Connect only to one reviewed IPv4 while authenticating the issuer host.

    The URL hostname remains the HTTP ``Host`` value, TLS SNI value, and
    certificate hostname.  The TCP connection is opened directly against the
    reviewed numeric address; this class never asks a resolver, discovers a
    proxy, follows a redirect, or retries a request.
    """

    def __init__(
        self,
        *,
        issuer: str,
        pinned_public_ipv4: str,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self._hostname = _issuer_hostname(issuer)
        self._pinned_public_ipv4 = _canonical_global_public_ipv4(
            pinned_public_ipv4
        )
        self._ssl_context = ssl_context or ssl.create_default_context()
        _require_verifying_context(self._ssl_context)

    def get_json(
        self,
        *,
        url: str,
        timeout_seconds: int,
        maximum_bytes: int,
    ) -> Mapping[str, Any]:
        return self._request_json(
            method="GET",
            url=url,
            body=None,
            headers={"Accept": "application/json"},
            timeout_seconds=timeout_seconds,
            maximum_bytes=maximum_bytes,
        )

    def post_form_json(
        self,
        *,
        url: str,
        form: Mapping[str, str],
        timeout_seconds: int,
        maximum_bytes: int,
    ) -> Mapping[str, Any]:
        if (
            not isinstance(form, Mapping)
            or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in form.items()
            )
        ):
            raise RuntimeError("OIDC request form is invalid")
        try:
            body = urlencode(dict(form)).encode("ascii")
        except (UnicodeError, ValueError, TypeError):
            raise RuntimeError("OIDC request form is invalid") from None
        return self._request_json(
            method="POST",
            url=url,
            body=body,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            timeout_seconds=timeout_seconds,
            maximum_bytes=maximum_bytes,
        )

    def _request_json(
        self,
        *,
        method: str,
        url: str,
        body: bytes | None,
        headers: Mapping[str, str],
        timeout_seconds: int,
        maximum_bytes: int,
    ) -> Mapping[str, Any]:
        target = _same_origin_target(url, hostname=self._hostname)
        if (
            type(timeout_seconds) is not int
            or timeout_seconds <= 0
            or type(maximum_bytes) is not int
            or maximum_bytes <= 0
        ):
            raise RuntimeError("OIDC transport bounds are invalid")
        _require_verifying_context(self._ssl_context)
        connection = _PinnedHttpsConnection(
            hostname=self._hostname,
            pinned_public_ipv4=self._pinned_public_ipv4,
            timeout=timeout_seconds,
            context=self._ssl_context,
        )
        response = None
        try:
            request_headers = {"Host": self._hostname, **dict(headers)}
            connection.request(
                method,
                target,
                body=body,
                headers=request_headers,
            )
            response = connection.getresponse()
            status = getattr(response, "status", None)
            content_type = response.headers.get_content_type()
            if status != 200 or content_type not in {
                "application/json",
                "application/jwk-set+json",
            }:
                raise RuntimeError("OIDC response protocol is invalid")
            raw = response.read(maximum_bytes + 1)
        except RuntimeError:
            raise
        except (
            HTTPException,
            OSError,
            TimeoutError,
            ValueError,
            ssl.SSLError,
        ):
            raise RuntimeError("OIDC transport failed") from None
        finally:
            if response is not None:
                try:
                    response.close()
                except BaseException:
                    pass
            try:
                connection.close()
            except BaseException:
                pass
        if len(raw) > maximum_bytes:
            raise RuntimeError("OIDC response exceeded its bound")
        try:
            value = json.loads(raw.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RuntimeError("OIDC response JSON is invalid") from None
        if not isinstance(value, Mapping):
            raise RuntimeError("OIDC response JSON is not an object")
        return value


class _PinnedHttpsConnection(HTTPSConnection):
    def __init__(
        self,
        *,
        hostname: str,
        pinned_public_ipv4: str,
        timeout: int,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(
            host=hostname,
            port=443,
            timeout=timeout,
            context=context,
        )
        self._pinned_public_ipv4 = pinned_public_ipv4

    def connect(self) -> None:
        if self._tunnel_host is not None:
            raise OSError("OIDC tunnels are not allowed")
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            raw_socket.settimeout(self.timeout)
            raw_socket.connect((self._pinned_public_ipv4, 443))
            self.sock = self._context.wrap_socket(
                raw_socket,
                server_hostname=self.host,
            )
        except BaseException:
            raw_socket.close()
            raise


def _issuer_hostname(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError):
        raise ValueError("OIDC pinned issuer is invalid") from None
    hostname = parsed.hostname
    if (
        not isinstance(value, str)
        or not value.isascii()
        or not isinstance(hostname, str)
        or parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.netloc != hostname
        or hostname != hostname.lower()
        or port is not None
        or parsed.query
        or parsed.fragment
        or value.endswith("/")
        or any(token in parsed.path for token in ("%", "\\", "//", "/./", "/../"))
        or _DNS_NAME.fullmatch(hostname) is None
        or not any(character.isalpha() for character in hostname.rsplit(".", 1)[-1])
        or hostname.endswith((".test", ".localhost", ".local", ".invalid"))
    ):
        raise ValueError("OIDC pinned issuer is invalid")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("OIDC pinned issuer is invalid")
    return hostname


def _canonical_global_public_ipv4(value: str) -> str:
    if not isinstance(value, str) or not value.isascii():
        raise ValueError("OIDC pinned address is invalid")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError("OIDC pinned address is invalid") from None
    if (
        not isinstance(address, ipaddress.IPv4Address)
        or str(address) != value
        or not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        raise ValueError("OIDC pinned address is invalid")
    return value


def _same_origin_target(value: str, *, hostname: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError):
        raise RuntimeError("OIDC request URL is invalid") from None
    if (
        parsed.scheme != "https"
        or parsed.hostname != hostname
        or parsed.netloc != hostname
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.fragment
        or not value.isascii()
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        or any(token in parsed.path for token in ("%", "\\", "//", "/./", "/../"))
    ):
        raise RuntimeError("OIDC request origin is invalid")
    path = parsed.path or "/"
    return path + (("?" + parsed.query) if parsed.query else "")


def _require_verifying_context(context: ssl.SSLContext) -> None:
    if (
        not isinstance(context, ssl.SSLContext)
        or context.check_hostname is not True
        or context.verify_mode != ssl.CERT_REQUIRED
    ):
        raise ValueError("OIDC TLS context is not verifying")


__all__ = ["PinnedPublicIpOidcJsonTransport"]
