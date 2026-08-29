"""Bounded raw ASGI 3 boundary for the IAM HTTP kernel."""

from __future__ import annotations

import asyncio
import re
import unicodedata
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple
from urllib.parse import unquote_to_bytes

from .contracts import HttpHeader, HttpRequest, HttpResponse
from .iam import IamHttpTransport


AsgiReceive = Callable[[], Awaitable[Dict[str, Any]]]
AsgiSend = Callable[[Dict[str, Any]], Awaitable[None]]


_LOWERCASE_HEADER_NAME = re.compile(rb"^[!#$%&'*+.^_`|~0-9a-z-]+$")
_PERCENT_ESCAPE = re.compile(rb"%[0-9A-Fa-f]{2}")
_MAXIMUM_HEADER_PAIRS = 100
_MAXIMUM_HEADER_COMPONENT_BYTES = 8192
_MAXIMUM_HEADER_BYTES = 32768
_MAXIMUM_QUERY_BYTES = 8192
_MAXIMUM_RAW_PATH_BYTES = 2048
_MAXIMUM_CONTENT_LENGTH = 2**63 - 1
_DISPATCH_OBSERVATION_SECONDS = 0.005


class _MalformedScope(Exception):
    def __init__(self, *, path: str, issue_code: str) -> None:
        self.path = path
        self.issue_code = issue_code
        super().__init__(issue_code)


def _scope_headers(
    scope: Dict[str, Any],
    *,
    maximum_header_bytes: int,
) -> Tuple[Tuple[HttpHeader, ...], Optional[int]]:
    raw_headers = scope.get("headers", ())
    if not isinstance(raw_headers, (tuple, list)):
        raise _MalformedScope(path="headers", issue_code="INVALID_TYPE")
    if len(raw_headers) > _MAXIMUM_HEADER_PAIRS:
        raise _MalformedScope(path="headers", issue_code="TOO_LARGE")
    headers = []
    total_size = 0
    for item in raw_headers:
        if (
            not isinstance(item, (tuple, list))
            or len(item) != 2
            or not isinstance(item[0], bytes)
            or not isinstance(item[1], bytes)
        ):
            raise _MalformedScope(path="headers", issue_code="INVALID_TYPE")
        name = bytes(item[0])
        value = bytes(item[1])
        total_size += len(name) + len(value)
        if (
            len(name) > _MAXIMUM_HEADER_COMPONENT_BYTES
            or len(value) > _MAXIMUM_HEADER_COMPONENT_BYTES
            or total_size > maximum_header_bytes
        ):
            raise _MalformedScope(path="headers", issue_code="TOO_LARGE")
        if not name or _LOWERCASE_HEADER_NAME.fullmatch(name) is None:
            raise _MalformedScope(path="headers", issue_code="INVALID_FORMAT")
        if any(byte < 32 or byte == 127 for byte in value):
            raise _MalformedScope(path="headers", issue_code="INVALID_FORMAT")
        headers.append(HttpHeader(name, value))

    content_lengths = [
        header.value for header in headers if header.name == b"content-length"
    ]
    transfer_encodings = [
        header.value for header in headers if header.name == b"transfer-encoding"
    ]
    if transfer_encodings:
        raise _MalformedScope(
            path="headers",
            issue_code="CONFLICT" if content_lengths else "INVALID_FORMAT",
        )
    if len(content_lengths) > 1:
        raise _MalformedScope(path="headers", issue_code="CONFLICT")
    declared = (
        None
        if not content_lengths
        else _parse_declared_content_length(content_lengths[0])
    )
    return tuple(headers), declared


def _parse_declared_content_length(raw: bytes) -> int:
    if not raw or not all(48 <= byte <= 57 for byte in raw):
        raise _MalformedScope(path="headers", issue_code="INVALID_FORMAT")
    # Nineteen decimal digits are enough to represent the signed 64-bit bound.
    # Checking the text length first prevents Python's integer digit guard (and
    # unbounded parse work) from becoming an exception-shaped protocol oracle.
    if len(raw) > 19:
        raise _MalformedScope(path="body", issue_code="TOO_LARGE")
    value = int(raw)
    if value > _MAXIMUM_CONTENT_LENGTH:
        raise _MalformedScope(path="body", issue_code="TOO_LARGE")
    return value


def _valid_percent_encoding(raw_path: bytes) -> bool:
    index = 0
    while index < len(raw_path):
        if raw_path[index : index + 1] == b"%":
            if (
                index + 3 > len(raw_path)
                or _PERCENT_ESCAPE.fullmatch(raw_path[index : index + 3]) is None
            ):
                return False
            # Encoded separators, NUL and percent itself create path aliases or
            # a second decoding opportunity and are outside the IAM grammar.
            if raw_path[index + 1 : index + 3].lower() in {
                b"00",
                b"25",
                b"2f",
                b"5c",
            }:
                return False
            index += 3
        else:
            index += 1
    return True


def _scope_path_is_valid(path: str, raw_path: Any) -> bool:
    if not isinstance(raw_path, bytes) or not raw_path:
        return False
    if len(raw_path) > _MAXIMUM_RAW_PATH_BYTES or not _valid_percent_encoding(raw_path):
        return False
    try:
        decoded = unquote_to_bytes(raw_path).decode("utf-8")
        encoded_path = path.encode("utf-8")
    except (UnicodeDecodeError, UnicodeEncodeError):
        return False
    return (
        decoded == path
        and encoded_path == unquote_to_bytes(raw_path)
        and unicodedata.normalize("NFC", path) == path
    )


async def _send_response(send: AsgiSend, response: HttpResponse) -> None:
    try:
        await send(
            {
                "type": "http.response.start",
                "status": response.status_code,
                "headers": tuple(
                    (header.name, header.value) for header in response.headers
                ),
            }
        )
    except OSError:
        return
    try:
        await send(
            {
                "type": "http.response.body",
                "body": response.body,
                "more_body": False,
            }
        )
    except OSError:
        return


async def _cancel_receive(task: "asyncio.Task[Dict[str, Any]]") -> None:
    if task.done():
        return
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


def _consume_background_result(future: "asyncio.Future[HttpResponse]") -> None:
    try:
        future.result()
    except BaseException:
        # The transport itself closes application exceptions.  This final guard
        # prevents an executor/runtime shutdown fault from becoming an unhandled
        # event-loop callback; no exception object is logged or serialized.
        pass


class IamAsgiApplication:
    """Read one bounded HTTP request and dispatch it at most once."""

    def __init__(
        self,
        transport: IamHttpTransport,
        *,
        request_timeout_seconds: float = 10.0,
        maximum_header_bytes: int = 32768,
    ) -> None:
        if request_timeout_seconds <= 0:
            raise ValueError("request_timeout_seconds must be positive")
        if maximum_header_bytes <= 0:
            raise ValueError("maximum_header_bytes must be positive")
        self._transport = transport
        self._request_timeout_seconds = request_timeout_seconds
        self._maximum_header_bytes = min(
            maximum_header_bytes,
            _MAXIMUM_HEADER_BYTES,
        )

    async def __call__(
        self,
        scope: Dict[str, Any],
        receive: AsgiReceive,
        send: AsgiSend,
    ) -> None:
        if scope.get("type") != "http":
            raise RuntimeError("IAM ASGI application only accepts HTTP scopes")

        method_value = scope.get("method", "")
        scheme_value = scope.get("scheme", "")
        path_value = scope.get("path", "")
        query_string = scope.get("query_string", b"")
        scope_is_valid = all(
            isinstance(value, str)
            for value in (method_value, scheme_value, path_value)
        ) and isinstance(query_string, bytes) and (
            len(query_string) <= _MAXIMUM_QUERY_BYTES
        )
        method = method_value if isinstance(method_value, str) else "OTHER"
        scheme = scheme_value if isinstance(scheme_value, str) else "invalid"
        path = path_value if isinstance(path_value, str) else "/invalid"
        if not isinstance(query_string, bytes):
            query_string = b""
        scope_failure_path = "request"
        scope_failure_code = "INVALID_FORMAT"
        try:
            headers, declared = _scope_headers(
                scope,
                maximum_header_bytes=self._maximum_header_bytes,
            )
        except _MalformedScope as error:
            headers = ()
            declared = None
            scope_is_valid = False
            scope_failure_path = error.path
            scope_failure_code = error.issue_code
        raw_path = scope.get("raw_path")
        if not isinstance(path_value, str) or not _scope_path_is_valid(path, raw_path):
            scope_is_valid = False
            scope_failure_path = "request"
            scope_failure_code = "INVALID_FORMAT"

        # Never pass a malformed/surrogate path back into route matching while
        # constructing the fail-closed response.
        response_path = path if scope_is_valid else "/invalid"
        request = HttpRequest(
            method=method,
            scheme=scheme,
            path=response_path,
            raw_query_string=query_string,
            headers=headers,
        )
        if not scope_is_valid:
            await _send_response(
                send,
                self._transport.invalid_request(
                    request,
                    path=scope_failure_path,
                    issue_code=scope_failure_code,
                ),
            )
            return

        body_limit = self._transport.body_limit_for(method=method, path=path)
        if body_limit < 0 and method != "OPTIONS":
            await _send_response(send, self._transport.handle(request))
            return
        if method == "OPTIONS":
            body_limit = 0
        if declared is not None and declared > body_limit:
            await _send_response(
                send,
                self._transport.invalid_request(
                    request,
                    path="body",
                    issue_code="TOO_LARGE",
                ),
            )
            return

        body = bytearray()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._request_timeout_seconds
        complete = False
        while not complete:
            remaining = deadline - loop.time()
            if remaining <= 0:
                await _send_response(send, self._transport.unavailable(request))
                return
            try:
                message = await asyncio.wait_for(receive(), timeout=remaining)
            except (asyncio.TimeoutError, TimeoutError):
                await _send_response(send, self._transport.unavailable(request))
                return
            except Exception:
                await _send_response(send, self._transport.unavailable(request))
                return

            if not isinstance(message, dict):
                await _send_response(
                    send,
                    self._transport.invalid_request(
                        request,
                        path="request",
                        issue_code="INVALID_TYPE",
                    ),
                )
                return
            message_type = message.get("type")
            if message_type == "http.disconnect":
                return
            if message_type != "http.request":
                await _send_response(
                    send,
                    self._transport.invalid_request(
                        request,
                        path="request",
                        issue_code="INVALID_FORMAT",
                    ),
                )
                return
            chunk = message.get("body", b"")
            more_body = message.get("more_body", False)
            if not isinstance(chunk, bytes) or not isinstance(more_body, bool):
                await _send_response(
                    send,
                    self._transport.invalid_request(
                        request,
                        path="body",
                        issue_code="INVALID_TYPE",
                    ),
                )
                return
            remaining_capacity = body_limit + 1 - len(body)
            if remaining_capacity > 0:
                body.extend(chunk[:remaining_capacity])
            if len(body) > body_limit:
                request = HttpRequest(
                    method=method,
                    scheme=scheme,
                    path=path,
                    raw_query_string=query_string,
                    headers=headers,
                    body=bytes(body),
                )
                await _send_response(send, self._transport.handle(request))
                return
            complete = not more_body

        request = HttpRequest(
            method=method,
            scheme=scheme,
            path=path,
            raw_query_string=query_string,
            headers=headers,
            body=bytes(body),
        )
        remaining = deadline - loop.time()
        if remaining <= 0:
            await _send_response(send, self._transport.unavailable(request))
            return

        # The protocol kernel and injected dispatcher are deliberately
        # synchronous contracts.  Execute them outside the event-loop thread so
        # the ASGI lifecycle can still observe the total deadline and a client
        # disconnect without invoking the command a second time.
        dispatch_future = loop.run_in_executor(None, self._transport.handle, request)
        observation_window = min(
            remaining,
            _DISPATCH_OBSERVATION_SECONDS,
        )
        completed, _ = await asyncio.wait(
            {dispatch_future},
            timeout=observation_window,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if dispatch_future in completed:
            await _send_response(send, dispatch_future.result())
            return

        remaining = deadline - loop.time()
        if remaining <= 0:
            dispatch_future.add_done_callback(_consume_background_result)
            await _send_response(
                send,
                self._transport.deadline_exceeded(request),
            )
            return

        disconnect_task = asyncio.create_task(receive())
        completed, _ = await asyncio.wait(
            {dispatch_future, disconnect_task},
            timeout=remaining,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if dispatch_future in completed:
            await _cancel_receive(disconnect_task)
            await _send_response(send, dispatch_future.result())
            return

        if disconnect_task in completed:
            try:
                lifecycle_message = disconnect_task.result()
            except BaseException:
                lifecycle_message = {"type": "http.disconnect"}
            if (
                isinstance(lifecycle_message, dict)
                and lifecycle_message.get("type") == "http.disconnect"
            ):
                dispatch_future.add_done_callback(_consume_background_result)
                return

            # A post-body request event is not a second request body and cannot
            # authorize a retry.  Treat the connection as unusable and let the
            # one in-flight application call complete independently.
            dispatch_future.add_done_callback(_consume_background_result)
            return

        await _cancel_receive(disconnect_task)
        dispatch_future.add_done_callback(_consume_background_result)
        await _send_response(
            send,
            self._transport.deadline_exceeded(request),
        )
