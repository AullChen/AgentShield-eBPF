"""Run-scoped, checkpoint-only AgentShield ingest client.

The client deliberately has no management API. Registration and Run cleanup
belong to a trusted supervisor that does not share its management credential or
socket with the Agent process.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import http.client
import ipaddress
import json
import math
import re
import ssl
import threading
import time
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit
import uuid


_CHECKPOINT_TYPES = frozenset(
    {
        "run_started",
        "llm_request",
        "llm_response",
        "tool_planned",
        "tool_started",
        "tool_finished",
        "run_finished",
        "run_failed",
    }
)
_RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_IDEMPOTENCY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAX_REQUEST_BYTES = 64 << 10
_MAX_RESPONSE_BYTES = 128 << 10
_MAX_STRING_BYTES = 1024
_MAX_MAP_KEY_BYTES = 128
_MAX_SUMMARY_BYTES = 4096
_MAX_MAP_ENTRIES = 32
_RETRYABLE_STATUSES = frozenset({429, 503})


class IngestError(Exception):
    """Base class for safe-to-display ingest failures."""

    def __repr__(self) -> str:
        return f"{type(self).__name__}({str(self)!r})"


class IngestHTTPError(IngestError):
    """The ingest endpoint returned a non-success status."""

    def __init__(self, status: int) -> None:
        self.status = status
        super().__init__(f"checkpoint ingest failed with HTTP status {status}")


class IngestTransportError(IngestError):
    """The request outcome is unknown because transport failed."""

    def __init__(self) -> None:
        super().__init__(
            "checkpoint delivery outcome is unknown; retry the pending checkpoint"
        )


class IngestProtocolError(IngestError):
    """The endpoint returned an invalid or unsafe response."""

    def __init__(self) -> None:
        super().__init__(
            "checkpoint response is invalid; retry the pending checkpoint"
        )


class IngestStateError(IngestError):
    """The client cannot safely start the requested operation."""


@dataclass(frozen=True, repr=False)
class _PendingCheckpoint:
    body: bytes
    sequence: int
    idempotency_key: str
    checkpoint_type: str
    client_time: str

    def __repr__(self) -> str:
        return (
            "_PendingCheckpoint(body=<redacted>, "
            f"sequence={self.sequence}, idempotency_key=<redacted>)"
        )


@dataclass(frozen=True)
class _Endpoint:
    scheme: str
    host: str
    port: int | None
    display_url: str


@dataclass(frozen=True)
class _Response:
    status: int
    content_type: str
    retry_after: str | None
    body: bytes


class IngestClient:
    """Send semantic checkpoints for exactly one registered Agent Run.

    Calls are serialized so concurrent callers cannot deliver sequence gaps.
    An ambiguous transport or response failure retains the exact serialized
    request; call :meth:`retry_pending` before attempting a new checkpoint.
    """

    def __init__(
        self,
        base_url: str,
        run_id: str,
        token: str,
        *,
        timeout: float = 5.0,
        max_retries: int = 2,
        retry_backoff: float = 0.1,
        initial_sequence: int = 1,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self._endpoint = _parse_endpoint(base_url)
        self._run_id = _validate_run_id(run_id)
        self._token = _validate_token(token)
        self._timeout = _bounded_float("timeout", timeout, minimum=0.001, maximum=300.0)
        self._retry_backoff = _bounded_float(
            "retry_backoff", retry_backoff, minimum=0.0, maximum=1.0
        )
        if isinstance(max_retries, bool) or not isinstance(max_retries, int):
            raise ValueError("max_retries must be an integer")
        if not 0 <= max_retries <= 3:
            raise ValueError("max_retries must be between 0 and 3")
        if isinstance(initial_sequence, bool) or not isinstance(initial_sequence, int):
            raise ValueError("initial_sequence must be an integer")
        if not 1 <= initial_sequence <= (1 << 64) - 1:
            raise ValueError("initial_sequence must be a positive uint64")
        if ssl_context is not None and self._endpoint.scheme != "https":
            raise ValueError("ssl_context is valid only for an HTTPS base URL")

        self._max_retries = max_retries
        self._next_sequence = initial_sequence
        self._ssl_context = ssl_context
        self._lock = threading.Lock()
        self._pending: _PendingCheckpoint | None = None

    def __repr__(self) -> str:
        return (
            f"IngestClient(base_url={self._endpoint.display_url!r}, "
            f"run_id={self._run_id!r}, token=<redacted>, "
            f"timeout={self._timeout!r}, max_retries={self._max_retries})"
        )

    @property
    def run_id(self) -> str:
        return self._run_id

    def checkpoint(
        self,
        checkpoint_type: str,
        *,
        phase: str | None = None,
        tool_name: str | None = None,
        summary: str | None = None,
        labels: Mapping[str, str] | None = None,
        metadata: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
    ) -> Mapping[str, Any]:
        """Send one checkpoint and return its server-authored receipt.

        The checkpoint type and optional fields are deliberately explicit: a
        caller cannot use this method to send trusted Run, scope, policy, or
        server-clock fields.
        """

        with self._lock:
            if self._pending is not None:
                raise IngestStateError(
                    "a checkpoint delivery is unresolved; call retry_pending first"
                )
            pending = self._build_checkpoint(
                checkpoint_type=checkpoint_type,
                phase=phase,
                tool_name=tool_name,
                summary=summary,
                labels=labels,
                metadata=metadata,
                idempotency_key=idempotency_key,
            )
            self._pending = pending
            try:
                receipt = self._send(pending)
            except IngestHTTPError:
                # A received HTTP failure is a definite non-acceptance under the
                # ingest contract. Ambiguous transport/protocol failures retain
                # the pending bytes instead.
                self._pending = None
                raise
            except (IngestTransportError, IngestProtocolError):
                raise
            self._accept_pending(pending)
            return receipt

    def retry_pending(self) -> Mapping[str, Any]:
        """Retry the exact bytes retained after an ambiguous delivery failure."""

        with self._lock:
            pending = self._pending
            if pending is None:
                raise IngestStateError("there is no pending checkpoint to retry")
            receipt = self._send(pending)
            self._accept_pending(pending)
            return receipt

    def _accept_pending(self, pending: _PendingCheckpoint) -> None:
        if pending.sequence == (1 << 64) - 1:
            self._pending = None
            self._next_sequence = 0
            return
        self._next_sequence = pending.sequence + 1
        self._pending = None

    def _build_checkpoint(
        self,
        *,
        checkpoint_type: str,
        phase: str | None,
        tool_name: str | None,
        summary: str | None,
        labels: Mapping[str, str] | None,
        metadata: Mapping[str, str] | None,
        idempotency_key: str | None,
    ) -> _PendingCheckpoint:
        if self._next_sequence == 0:
            raise IngestStateError("checkpoint sequence space is exhausted")
        if not isinstance(checkpoint_type, str):
            raise TypeError("checkpoint_type must be a string")
        if checkpoint_type not in _CHECKPOINT_TYPES:
            raise ValueError("checkpoint_type is unsupported")

        sequence = self._next_sequence
        key = uuid.uuid4().hex if idempotency_key is None else idempotency_key
        if not isinstance(key, str) or not _IDEMPOTENCY_PATTERN.fullmatch(key):
            raise ValueError("idempotency_key has an invalid format")

        client_time = str(time.time_ns())
        payload: dict[str, Any] = {
            "sequence": str(sequence),
            "idempotency_key": key,
            "type": checkpoint_type,
            "client_reported_unix_ns": client_time,
        }
        _add_optional_string(payload, "phase", phase, _MAX_STRING_BYTES)
        _add_optional_string(payload, "tool_name", tool_name, _MAX_STRING_BYTES)
        _add_optional_string(payload, "summary", summary, _MAX_SUMMARY_BYTES)
        if labels is not None:
            payload["labels"] = _copy_string_map("labels", labels)
        if metadata is not None:
            payload["metadata"] = _copy_string_map("metadata", metadata)

        body = json.dumps(
            payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        if len(body) > _MAX_REQUEST_BYTES:
            raise ValueError("checkpoint payload exceeds the 64 KiB body limit")
        return _PendingCheckpoint(
            body=body,
            sequence=sequence,
            idempotency_key=key,
            checkpoint_type=checkpoint_type,
            client_time=client_time,
        )

    def _send(self, pending: _PendingCheckpoint) -> Mapping[str, Any]:
        for attempt in range(self._max_retries + 1):
            response = self._request_once(pending.body)
            if response.status in (200, 201):
                return self._decode_receipt(response, pending)
            if response.status in _RETRYABLE_STATUSES and attempt < self._max_retries:
                delay = _retry_delay(
                    response.retry_after, self._retry_backoff, attempt
                )
                if delay > 0:
                    time.sleep(delay)
                continue
            raise IngestHTTPError(response.status)
        raise AssertionError("unreachable")

    def _request_once(self, body: bytes) -> _Response:
        connection: http.client.HTTPConnection | None = None
        failed = False
        response: _Response | None = None
        try:
            connection = self._connection()
            connection.request(
                "POST",
                f"/ingest/v1/runs/{self._run_id}/checkpoints",
                body=body,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {self._token}",
                    "Connection": "close",
                    "Content-Type": "application/json",
                    "User-Agent": "agentshield-ingest-python/0.1",
                },
            )
            raw = connection.getresponse()
            response_body = raw.read(_MAX_RESPONSE_BYTES + 1)
            if len(response_body) > _MAX_RESPONSE_BYTES:
                response = None
            else:
                response = _Response(
                    status=raw.status,
                    content_type=raw.getheader("Content-Type", ""),
                    retry_after=raw.getheader("Retry-After"),
                    body=response_body,
                )
        except (OSError, http.client.HTTPException):
            failed = True
        finally:
            if connection is not None:
                try:
                    connection.close()
                except OSError:
                    pass

        if failed:
            raise IngestTransportError()
        if response is None:
            raise IngestProtocolError()
        return response

    def _connection(self) -> http.client.HTTPConnection:
        if self._endpoint.scheme == "https":
            context = self._ssl_context or ssl.create_default_context()
            return http.client.HTTPSConnection(
                self._endpoint.host,
                self._endpoint.port,
                timeout=self._timeout,
                context=context,
            )
        return http.client.HTTPConnection(
            self._endpoint.host,
            self._endpoint.port,
            timeout=self._timeout,
        )

    def _decode_receipt(
        self, response: _Response, pending: _PendingCheckpoint
    ) -> Mapping[str, Any]:
        media_type = response.content_type.partition(";")[0].strip().lower()
        if media_type != "application/json":
            raise IngestProtocolError()

        decoded: Any = None
        try:
            decoded = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            decoded = None
        if not isinstance(decoded, dict):
            raise IngestProtocolError()

        required_strings = (
            "checkpoint_id",
            "run_id",
            "sequence",
            "server_received_monotonic_ns",
            "server_received_unix_ns",
            "clock_calibration_error_ns",
            "type",
            "source",
        )
        if any(not isinstance(decoded.get(name), str) for name in required_strings):
            raise IngestProtocolError()
        if (
            decoded["run_id"] != self._run_id
            or decoded["sequence"] != str(pending.sequence)
            or decoded.get("idempotency_key") != pending.idempotency_key
            or decoded.get("client_reported_unix_ns") != pending.client_time
            or decoded["type"] != pending.checkpoint_type
            or decoded["source"] != "agent_claim"
        ):
            raise IngestProtocolError()
        if not decoded["checkpoint_id"] or len(decoded["checkpoint_id"]) > 128:
            raise IngestProtocolError()
        if not _is_uint64_decimal(decoded["sequence"], positive=True):
            raise IngestProtocolError()
        if not _is_uint64_decimal(
            decoded["server_received_monotonic_ns"], positive=True
        ) or not _is_uint64_decimal(
            decoded["server_received_unix_ns"], positive=True
        ) or not _is_uint64_decimal(
            decoded["clock_calibration_error_ns"], positive=False
        ):
            raise IngestProtocolError()
        return MappingProxyType(decoded)


def _parse_endpoint(base_url: str) -> _Endpoint:
    if not isinstance(base_url, str):
        raise TypeError("base_url must be a string")
    parsed = urlsplit(base_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("base_url scheme must be http or https")
    if (
        not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise ValueError("base_url must contain only scheme and authority")
    host = parsed.hostname
    if host is None or any(ord(character) <= 32 for character in host):
        raise ValueError("base_url host is invalid")
    try:
        ascii_host = host.encode("idna").decode("ascii")
        port = parsed.port
    except (UnicodeError, ValueError):
        raise ValueError("base_url authority is invalid") from None
    if not re.fullmatch(r"[A-Za-z0-9.:-]+", ascii_host):
        raise ValueError("base_url host is invalid")
    if parsed.scheme == "http" and not _is_loopback_host(ascii_host):
        raise ValueError("non-loopback checkpoint ingest requires HTTPS")
    display_host = f"[{ascii_host}]" if ":" in ascii_host else ascii_host
    display_url = f"{parsed.scheme}://{display_host}"
    if port is not None:
        display_url += f":{port}"
    return _Endpoint(parsed.scheme, ascii_host, port, display_url)


def _is_loopback_host(host: str) -> bool:
    if host.lower().rstrip(".") == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_run_id(run_id: str) -> str:
    if not isinstance(run_id, str) or not _RUN_ID_PATTERN.fullmatch(run_id):
        raise ValueError("run_id has an invalid format")
    return run_id


def _validate_token(token: str) -> str:
    if not isinstance(token, str):
        raise TypeError("token must be a string")
    if not token or len(token) > 4096:
        raise ValueError("token has an invalid format")
    if any(not 33 <= ord(character) <= 126 for character in token):
        raise ValueError("token has an invalid format")
    return token


def _bounded_float(name: str, value: float, *, minimum: float, maximum: float) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a finite number")
    try:
        result = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a finite number") from None
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise ValueError(f"{name} is outside the supported range")
    return result


def _add_optional_string(
    payload: dict[str, Any], name: str, value: str | None, limit: int
) -> None:
    if value is None:
        return
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    if len(value.encode("utf-8")) > limit:
        raise ValueError(f"{name} exceeds its byte limit")
    payload[name] = value


def _copy_string_map(name: str, value: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be a mapping")
    if len(value) > _MAX_MAP_ENTRIES:
        raise ValueError(f"{name} has too many entries")
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise TypeError(f"{name} keys and values must be strings")
        if not key.strip() or len(key.encode("utf-8")) > _MAX_MAP_KEY_BYTES:
            raise ValueError(f"{name} contains an invalid key")
        if len(item.encode("utf-8")) > _MAX_STRING_BYTES:
            raise ValueError(f"{name} contains an oversized value")
        result[key] = item
    return result


def _retry_delay(header: str | None, backoff: float, attempt: int) -> float:
    if (
        header is not None
        and header.isascii()
        and header.isdecimal()
        and len(header) <= 10
    ):
        return min(float(header), 1.0)
    return min(backoff * (2**attempt), 1.0)


def _is_uint64_decimal(value: str, *, positive: bool) -> bool:
    if not value or not value.isascii() or not value.isdecimal():
        return False
    canonical = value.lstrip("0") or "0"
    maximum = "18446744073709551615"
    if len(canonical) > len(maximum) or (
        len(canonical) == len(maximum) and canonical > maximum
    ):
        return False
    return canonical != "0" or not positive
