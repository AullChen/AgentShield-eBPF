"""Trusted AgentShield supervisor orchestration example.

The process/cgroup adapter is intentionally a protocol: a production adapter must
create the exact leaf cgroup and prepare a stopped task before calling
``supervise``.  This module owns the management socket and only hands checkpoint
credentials to the task.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import http.client
import json
import math
import os
import re
import socket
import stat
import struct
from typing import Mapping, Protocol
from urllib.parse import quote, urlsplit


_MAX_MANAGEMENT_RESPONSE = 64 << 10
_RUN_ID = re.compile(r"^[0-9a-f]{32}$")


class ManagementError(RuntimeError):
    """A deliberately body-free management transport/protocol error."""


class SupervisorError(RuntimeError):
    """A sanitized orchestration failure."""


@dataclass(frozen=True)
class RegistrationRequest:
    agent_name: str
    cgroup_path: str
    container_id: str = ""
    root_pid: int = 0
    profile_id: int = 0
    labels: Mapping[str, str] = field(default_factory=dict)

    def to_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "agent_name": self.agent_name,
            "cgroup_path": self.cgroup_path,
            "scope_mode": "leaf_exact",
        }
        if self.container_id:
            payload["container_id"] = self.container_id
        if self.root_pid:
            payload["root_pid"] = self.root_pid
        if self.profile_id:
            payload["profile_id"] = self.profile_id
        if self.labels:
            payload["labels"] = dict(self.labels)
        return payload


@dataclass(frozen=True, repr=False)
class AgentCredentials:
    """The complete and deliberately narrow capability passed to an Agent."""

    run_id: str
    checkpoint_url: str
    ingest_token: str = field(repr=False)

    def __repr__(self) -> str:
        return (
            "AgentCredentials("
            f"run_id={self.run_id!r}, checkpoint_url={self.checkpoint_url!r}, "
            "ingest_token=<redacted>)"
        )


@dataclass(frozen=True, repr=False)
class Registration:
    run_id: str
    cgroup_id: str
    instance_id: str
    scope_cookie: str
    cgroup_path: str
    scope_mode: str
    ingest_token: str = field(repr=False)
    token_expiry: str

    def __repr__(self) -> str:
        return (
            "Registration("
            f"run_id={self.run_id!r}, cgroup_id={self.cgroup_id!r}, "
            f"instance_id={self.instance_id!r}, scope_cookie={self.scope_cookie!r}, "
            f"cgroup_path={self.cgroup_path!r}, scope_mode={self.scope_mode!r}, "
            "ingest_token=<redacted>, "
            f"token_expiry={self.token_expiry!r})"
        )

    def agent_credentials(self, ingest_base_url: str) -> AgentCredentials:
        if not isinstance(ingest_base_url, str) or not ingest_base_url or any(
            ord(character) <= 32 for character in ingest_base_url
        ):
            raise SupervisorError("invalid checkpoint ingest base URL")
        parsed = urlsplit(ingest_base_url)
        try:
            parsed_port = parsed.port
        except ValueError:
            raise SupervisorError("invalid checkpoint ingest base URL") from None
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or "?" in ingest_base_url
            or "#" in ingest_base_url
            or parsed_port is not None
            and not 0 < parsed_port < 65536
        ):
            raise SupervisorError("invalid checkpoint ingest base URL")
        host = parsed.hostname
        assert host is not None
        rendered_host = f"[{host}]" if ":" in host else host
        base = f"{parsed.scheme}://{rendered_host}"
        if parsed_port is not None:
            base += f":{parsed_port}"
        return AgentCredentials(
            run_id=self.run_id,
            checkpoint_url=(
                f"{base}/ingest/v1/runs/{quote(self.run_id, safe='')}/checkpoints"
            ),
            ingest_token=self.ingest_token,
        )


@dataclass(frozen=True)
class FinishResult:
    run_id: str
    status: str
    ended_at: str


@dataclass(frozen=True)
class SupervisedResult:
    run_id: str
    exit_code: int
    finish: FinishResult


class PreparedTask(Protocol):
    """Adapter holding a stopped task and stable descriptor for its exact leaf."""

    @property
    def is_prepared(self) -> bool: ...

    @property
    def registration_request(self) -> RegistrationRequest: ...

    def confirms_registration(self, registration: Registration) -> bool: ...

    def confirm_stopped(self) -> None:
        """Fail unless the prepared root task remains stopped in the held leaf."""
        ...

    def start(self, credentials: AgentCredentials) -> None: ...

    def wait_for_scope_exit(self, timeout: float | None = None) -> int:
        """Return only after the root workload exited and the exact leaf is empty."""
        ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float, expected_uid: int) -> None:
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path
        self._expected_uid = expected_uid

    def connect(self) -> None:
        _verify_management_socket_path(self._socket_path, self._expected_uid)
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        try:
            connection.connect(self._socket_path)
            _verify_management_peer(connection, self._expected_uid)
        except BaseException:
            connection.close()
            raise
        self.sock = connection


def _verify_management_socket_path(socket_path: str, expected_uid: int) -> None:
    if expected_uid < 0:
        raise OSError("management socket credentials are unsupported")
    socket_stat = os.lstat(socket_path)
    if (
        not stat.S_ISSOCK(socket_stat.st_mode)
        or socket_stat.st_uid != expected_uid
        or socket_stat.st_mode & 0o077
    ):
        raise OSError("management socket is not owner-only")
    parent_stat = os.lstat(os.path.dirname(socket_path))
    if (
        not stat.S_ISDIR(parent_stat.st_mode)
        or parent_stat.st_uid != expected_uid
        or parent_stat.st_mode & 0o022
    ):
        raise OSError("management socket directory is not trusted")


def _verify_management_peer(connection: socket.socket, expected_uid: int) -> None:
    if not hasattr(socket, "SO_PEERCRED"):
        raise OSError("management peer credentials are unsupported")
    size = struct.calcsize("3i")
    credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size)
    peer_pid, peer_uid, _ = struct.unpack("3i", credentials)
    if peer_pid <= 0 or peer_uid != expected_uid:
        raise OSError("management peer identity mismatch")


class ManagementClient:
    """Owner-only registration/finish client; never pass this object to an Agent."""

    def __init__(self, socket_path: str, *, timeout: float = 5.0) -> None:
        if (
            not isinstance(socket_path, str)
            or not socket_path
            or not os.path.isabs(socket_path)
            or "\x00" in socket_path
        ):
            raise ValueError("management socket path must be absolute")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or not 0 < timeout <= 300
        ):
            raise ValueError("management timeout must be between zero and 300 seconds")
        self._socket_path = socket_path
        self._timeout = float(timeout)
        self._expected_uid = os.geteuid() if hasattr(os, "geteuid") else -1

    def __repr__(self) -> str:
        return "ManagementClient(socket_path=<owner-only Unix socket>)"

    def _open_connection(self) -> http.client.HTTPConnection:
        return _UnixHTTPConnection(
            self._socket_path, self._timeout, self._expected_uid
        )

    def _request_json(
        self,
        method: str,
        path: str,
        payload: Mapping[str, object],
        expected_status: int,
    ) -> Mapping[str, object]:
        try:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError):
            raise ManagementError("management request could not be encoded") from None
        connection = self._open_connection()
        try:
            connection.request(
                method,
                path,
                body=body,
                headers={
                    "Accept": "application/json",
                    "Connection": "close",
                    "Content-Type": "application/json",
                },
            )
            response = connection.getresponse()
            response_body = response.read(_MAX_MANAGEMENT_RESPONSE + 1)
        except BaseException:
            raise ManagementError("management API request failed") from None
        finally:
            try:
                connection.close()
            except BaseException:
                pass

        if len(response_body) > _MAX_MANAGEMENT_RESPONSE:
            raise ManagementError("management API response exceeded the size limit")
        if response.status != expected_status:
            raise ManagementError(
                f"management API returned HTTP {response.status}"
            )
        try:
            decoded = json.loads(response_body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ManagementError("management API returned invalid JSON") from None
        if not isinstance(decoded, dict):
            raise ManagementError("management API returned an invalid object")
        return decoded

    def register(self, request: RegistrationRequest) -> Registration:
        if not isinstance(request, RegistrationRequest):
            raise TypeError("request must be a RegistrationRequest")
        output = self._request_json(
            "POST", "/api/v1/agents/register", request.to_payload(), 201
        )
        required = (
            "run_id",
            "cgroup_id",
            "instance_id",
            "scope_cookie",
            "cgroup_path",
            "scope_mode",
            "ingest_token",
            "token_expiry",
        )
        if any(
            not isinstance(output.get(name), str) or not output[name]
            for name in required
        ):
            raise ManagementError("management registration response is incomplete")
        run_id = str(output["run_id"])
        if not _RUN_ID.fullmatch(run_id):
            raise ManagementError("management registration returned an invalid Run ID")
        for name in ("cgroup_id", "instance_id", "scope_cookie"):
            value = str(output[name])
            if not value.isdecimal() or int(value) == 0:
                raise ManagementError("management registration returned an invalid identity")
        if output["scope_mode"] != "leaf_exact":
            raise ManagementError("management registration returned an invalid scope mode")
        if output["cgroup_path"] != request.cgroup_path:
            raise ManagementError("management registration returned the wrong cgroup path")
        return Registration(
            run_id=run_id,
            cgroup_id=str(output["cgroup_id"]),
            instance_id=str(output["instance_id"]),
            scope_cookie=str(output["scope_cookie"]),
            cgroup_path=str(output["cgroup_path"]),
            scope_mode=str(output["scope_mode"]),
            ingest_token=str(output["ingest_token"]),
            token_expiry=str(output["token_expiry"]),
        )

    def finish(self, run_id: str) -> FinishResult:
        if not _RUN_ID.fullmatch(run_id):
            raise ValueError("invalid Run ID")
        output = self._request_json(
            "POST",
            f"/api/v1/agents/{quote(run_id, safe='')}/finish",
            {},
            200,
        )
        values = {name: output.get(name) for name in ("run_id", "status", "ended_at")}
        if any(not isinstance(value, str) or not value for value in values.values()):
            raise ManagementError("management finish response is incomplete")
        if values["run_id"] != run_id:
            raise ManagementError("management finish returned the wrong Run ID")
        if values["status"] not in {"finished", "failed", "expired"}:
            raise ManagementError("management finish returned an invalid terminal status")
        return FinishResult(
            run_id=str(values["run_id"]),
            status=str(values["status"]),
            ended_at=str(values["ended_at"]),
        )


def _wait_for_scope_exit(task: PreparedTask, timeout: float | None = None) -> int:
    exit_code = task.wait_for_scope_exit(timeout)
    if isinstance(exit_code, bool) or not isinstance(exit_code, int):
        raise TypeError("scope exit wait did not return an exit code")
    return exit_code


def _stop_and_confirm_scope_exit(task: PreparedTask, timeout: float) -> int | None:
    """Try TERM then KILL; root exit plus an empty held leaf is required."""

    for stop in (task.terminate, task.kill):
        try:
            stop()
        except BaseException:
            pass
        try:
            return _wait_for_scope_exit(task, timeout)
        except BaseException:
            pass
    return None


def _finish_after_exit(
    management: ManagementClient, registration: Registration
) -> FinishResult:
    try:
        return management.finish(registration.run_id)
    except BaseException:
        raise SupervisorError(
            "task exit was confirmed but management finish failed"
        ) from None


def supervise(
    management: ManagementClient,
    task: PreparedTask,
    *,
    ingest_base_url: str,
    stop_timeout: float = 5.0,
) -> SupervisedResult:
    """Run one prepared task without treating Agent claims as lifecycle facts.

    The adapter must return only after the root workload has exited and its held
    exact leaf is empty. No checkpoint, including ``run_finished``, can replace
    that trusted scope-exit observation.
    """

    if (
        isinstance(stop_timeout, bool)
        or not isinstance(stop_timeout, (int, float))
        or not math.isfinite(stop_timeout)
        or not 0 < stop_timeout <= 60
    ):
        raise SupervisorError("stop timeout must be between zero and 60 seconds")
    stop_timeout = float(stop_timeout)

    try:
        prepared = task.is_prepared
        request = task.registration_request
    except BaseException:
        raise SupervisorError("could not inspect prepared task state") from None
    if not prepared:
        raise SupervisorError("task must be prepared and stopped before registration")
    if not isinstance(request, RegistrationRequest):
        raise SupervisorError("prepared task returned an invalid registration request")

    try:
        registration = management.register(request)
    except BaseException:
        stopped = _stop_and_confirm_scope_exit(task, stop_timeout)
        if stopped is None:
            raise SupervisorError(
                "registration outcome is unknown and task exit was not confirmed"
            ) from None
        raise SupervisorError(
            "management registration failed; prepared task was stopped"
        ) from None

    try:
        if not task.confirms_registration(registration):
            raise SupervisorError("prepared scope does not match registration")
        task.confirm_stopped()
        credentials = registration.agent_credentials(ingest_base_url)
        task.start(credentials)
        exit_code = _wait_for_scope_exit(task)
    except BaseException as failure:
        exit_code = _stop_and_confirm_scope_exit(task, stop_timeout)
        if exit_code is None:
            raise SupervisorError(
                "task exit could not be confirmed; management Run remains active"
            ) from None
        finish = _finish_after_exit(management, registration)
        if isinstance(failure, KeyboardInterrupt):
            raise KeyboardInterrupt from None
        if isinstance(failure, SystemExit):
            raise SystemExit(1) from None
        raise SupervisorError(
            "task failed after registration; exit was confirmed and Run was finished"
        ) from None

    finish = _finish_after_exit(management, registration)
    return SupervisedResult(
        run_id=registration.run_id,
        exit_code=exit_code,
        finish=finish,
    )
