from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from supervisor import (  # noqa: E402
    AgentCredentials,
    FinishResult,
    ManagementClient,
    ManagementError,
    Registration,
    RegistrationRequest,
    SupervisorError,
    supervise,
)


RUN_ID = "0123456789abcdef0123456789abcdef"
TOKEN = "sensitive-ingest-token"
PROMPT = "full private prompt"


def registration() -> Registration:
    return Registration(
        run_id=RUN_ID,
        cgroup_id="101",
        instance_id="102",
        scope_cookie="103",
        cgroup_path="/sys/fs/cgroup/agentshield/demo/leaf",
        scope_mode="leaf_exact",
        ingest_token=TOKEN,
        token_expiry="2026-08-14T02:00:00Z",
    )


class FakeManagement:
    def __init__(
        self,
        timeline: list[str],
        *,
        fail_register: bool = False,
        fail_finish: bool = False,
    ) -> None:
        self.timeline = timeline
        self.fail_register = fail_register
        self.fail_finish = fail_finish
        self.finish_calls = 0

    def register(self, request: RegistrationRequest) -> Registration:
        self.timeline.append("register")
        if self.fail_register:
            raise RuntimeError(f"server leaked {TOKEN} {PROMPT}")
        return registration()

    def finish(self, run_id: str) -> FinishResult:
        self.timeline.append("finish")
        self.finish_calls += 1
        if "wait:observed" not in self.timeline:
            raise AssertionError("finish preceded trusted exit observation")
        if self.fail_finish:
            raise RuntimeError(f"finish leaked {TOKEN} {PROMPT}")
        return FinishResult(run_id=run_id, status="finished", ended_at="now")


class FakeTask:
    def __init__(
        self,
        timeline: list[str],
        *,
        prepared: bool = True,
        fail_start: bool = False,
        wait_failures: int = 0,
        matches_registration: bool = True,
    ) -> None:
        self.timeline = timeline
        self._prepared = prepared
        self.fail_start = fail_start
        self.wait_failures = wait_failures
        self.matches_registration = matches_registration
        self.credentials: AgentCredentials | None = None
        self.registration_request = RegistrationRequest(
            agent_name="demo-agent",
            cgroup_path="/sys/fs/cgroup/agentshield/demo/leaf",
            root_pid=123,
        )

    @property
    def is_prepared(self) -> bool:
        return self._prepared

    def start(self, credentials: AgentCredentials) -> None:
        self.credentials = credentials
        self.timeline.append("start")
        self.timeline.append("agent-claim:run_finished")
        if self.fail_start:
            raise RuntimeError(f"start leaked {credentials.ingest_token} {PROMPT}")

    def confirms_registration(self, registration: Registration) -> bool:
        self.timeline.append("confirm-registration")
        return self.matches_registration and registration.cgroup_path == self.registration_request.cgroup_path

    def confirm_stopped(self) -> None:
        self.timeline.append("confirm-stopped")

    def wait_for_scope_exit(self, timeout: float | None = None) -> int:
        self.timeline.append("wait")
        if self.wait_failures:
            self.wait_failures -= 1
            raise RuntimeError(f"wait leaked {TOKEN} {PROMPT}")
        self.timeline.append("wait:observed")
        return 7

    def terminate(self) -> None:
        self.timeline.append("terminate")

    def kill(self) -> None:
        self.timeline.append("kill")


class SupervisorTests(unittest.TestCase):
    def test_happy_path_finishes_only_after_observed_exit(self) -> None:
        timeline: list[str] = []
        management = FakeManagement(timeline)
        task = FakeTask(timeline)

        result = supervise(
            management, task, ingest_base_url="http://127.0.0.1:8181"
        )

        self.assertEqual(result.exit_code, 7)
        self.assertEqual(
            timeline,
            [
                "register",
                "confirm-registration",
                "confirm-stopped",
                "start",
                "agent-claim:run_finished",
                "wait",
                "wait:observed",
                "finish",
            ],
        )
        self.assertIsNotNone(task.credentials)
        credentials = task.credentials
        assert credentials is not None
        self.assertEqual(credentials.run_id, RUN_ID)
        self.assertEqual(
            credentials.checkpoint_url,
            f"http://127.0.0.1:8181/ingest/v1/runs/{RUN_ID}/checkpoints",
        )
        self.assertNotIn(TOKEN, repr(credentials))
        self.assertFalse(hasattr(credentials, "management_socket"))

    def test_unprepared_task_is_rejected_before_registration(self) -> None:
        timeline: list[str] = []
        with self.assertRaises(SupervisorError):
            supervise(
                FakeManagement(timeline),
                FakeTask(timeline, prepared=False),
                ingest_base_url="http://127.0.0.1:8181",
            )
        self.assertEqual(timeline, [])

    def test_start_failure_stops_waits_then_finishes_without_leaking(self) -> None:
        timeline: list[str] = []
        with self.assertRaises(SupervisorError) as raised:
            supervise(
                FakeManagement(timeline),
                FakeTask(timeline, fail_start=True),
                ingest_base_url="http://127.0.0.1:8181",
            )
        self.assertEqual(
            timeline,
            [
                "register",
                "confirm-registration",
                "confirm-stopped",
                "start",
                "agent-claim:run_finished",
                "terminate",
                "wait",
                "wait:observed",
                "finish",
            ],
        )
        self.assertNotIn(TOKEN, str(raised.exception))
        self.assertNotIn(PROMPT, str(raised.exception))

    def test_wait_failure_uses_terminate_and_wait_before_finish(self) -> None:
        timeline: list[str] = []
        with self.assertRaises(SupervisorError):
            supervise(
                FakeManagement(timeline),
                FakeTask(timeline, wait_failures=1),
                ingest_base_url="http://127.0.0.1:8181",
            )
        self.assertEqual(
            timeline[-4:], ["terminate", "wait", "wait:observed", "finish"]
        )

    def test_cleanup_escalates_to_kill_before_finish(self) -> None:
        timeline: list[str] = []
        with self.assertRaises(SupervisorError):
            supervise(
                FakeManagement(timeline),
                FakeTask(timeline, wait_failures=2),
                ingest_base_url="http://127.0.0.1:8181",
            )
        self.assertEqual(
            timeline[-6:],
            ["terminate", "wait", "kill", "wait", "wait:observed", "finish"],
        )

    def test_never_finishes_without_confirmed_exit(self) -> None:
        timeline: list[str] = []
        management = FakeManagement(timeline)
        task = FakeTask(timeline, fail_start=True, wait_failures=99)
        with self.assertRaises(SupervisorError) as raised:
            supervise(
                management, task, ingest_base_url="http://127.0.0.1:8181"
            )
        self.assertEqual(management.finish_calls, 0)
        self.assertEqual(timeline[-4:], ["terminate", "wait", "kill", "wait"])
        self.assertIn("remains active", str(raised.exception))
        self.assertNotIn(TOKEN, str(raised.exception))

    def test_registration_failure_stops_prepared_task_without_finish(self) -> None:
        timeline: list[str] = []
        management = FakeManagement(timeline, fail_register=True)
        with self.assertRaises(SupervisorError) as raised:
            supervise(
                management,
                FakeTask(timeline),
                ingest_base_url="http://127.0.0.1:8181",
            )
        self.assertEqual(
            timeline, ["register", "terminate", "wait", "wait:observed"]
        )
        self.assertEqual(management.finish_calls, 0)
        self.assertNotIn(TOKEN, str(raised.exception))
        self.assertNotIn(PROMPT, str(raised.exception))

    def test_finish_failure_is_sanitized_after_exit(self) -> None:
        timeline: list[str] = []
        management = FakeManagement(timeline, fail_finish=True)
        with self.assertRaises(SupervisorError) as raised:
            supervise(
                management,
                FakeTask(timeline),
                ingest_base_url="http://127.0.0.1:8181",
            )
        self.assertEqual(timeline[-3:], ["wait", "wait:observed", "finish"])
        rendered = repr(raised.exception) + str(raised.exception)
        self.assertNotIn(TOKEN, rendered)
        self.assertNotIn(PROMPT, rendered)

    def test_invalid_ingest_url_cleans_up_registered_task(self) -> None:
        timeline: list[str] = []
        with self.assertRaises(SupervisorError):
            supervise(
                FakeManagement(timeline),
                FakeTask(timeline),
                ingest_base_url="unix:///owner-only/management.sock",
            )
        self.assertEqual(
            timeline,
            ["register", "confirm-registration", "confirm-stopped", "terminate", "wait", "wait:observed", "finish"],
        )

    def test_registration_identity_mismatch_never_starts_task(self) -> None:
        timeline: list[str] = []
        with self.assertRaises(SupervisorError):
            supervise(
                FakeManagement(timeline),
                FakeTask(timeline, matches_registration=False),
                ingest_base_url="http://127.0.0.1:8181",
            )
        self.assertNotIn("start", timeline)
        self.assertEqual(timeline[-4:], ["terminate", "wait", "wait:observed", "finish"])

    def test_terminate_timeout_escalates_to_kill(self) -> None:
        timeline: list[str] = []

        class TimeoutTask(FakeTask):
            def wait_for_scope_exit(self, timeout: float | None = None) -> int:
                self.timeline.append(f"wait:{timeout}")
                if self.timeline.count("terminate"):
                    if not self.timeline.count("kill"):
                        raise TimeoutError("scope remains populated")
                    self.timeline.append("wait:observed")
                    return 9
                raise RuntimeError("workload wait failed")

        with self.assertRaises(SupervisorError):
            supervise(
                FakeManagement(timeline),
                TimeoutTask(timeline),
                ingest_base_url="http://127.0.0.1:8181",
                stop_timeout=0.01,
            )
        self.assertEqual(
            timeline[-6:],
            ["terminate", "wait:0.01", "kill", "wait:0.01", "wait:observed", "finish"],
        )


class FakeResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._body = io.BytesIO(body)

    def read(self, amount: int) -> bytes:
        return self._body.read(amount)


class FakeConnection:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.request_call: tuple[object, ...] | None = None
        self.closed = False

    def request(self, method: str, path: str, *, body: bytes, headers: object) -> None:
        self.request_call = (method, path, body, headers)

    def getresponse(self) -> FakeResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


class StubManagementClient(ManagementClient):
    def __init__(self, response: FakeResponse) -> None:
        super().__init__(str(Path.cwd().resolve() / "management.sock"))
        self.connection = FakeConnection(response)

    def _open_connection(self) -> FakeConnection:
        return self.connection


class ManagementClientTests(unittest.TestCase):
    def test_register_parses_response_and_redacts_capabilities(self) -> None:
        response = {
            "run_id": RUN_ID,
            "cgroup_id": "101",
            "instance_id": "102",
            "scope_cookie": "103",
            "cgroup_path": "/sys/fs/cgroup/agentshield/demo/leaf",
            "scope_mode": "leaf_exact",
            "ingest_token": TOKEN,
            "token_expiry": "2026-08-14T02:00:00Z",
        }
        client = StubManagementClient(
            FakeResponse(201, json.dumps(response).encode("utf-8"))
        )

        result = client.register(
            RegistrationRequest(
                agent_name="demo-agent",
                cgroup_path="/sys/fs/cgroup/agentshield/demo/leaf",
            )
        )

        self.assertEqual(result.ingest_token, TOKEN)
        self.assertNotIn(TOKEN, repr(result))
        self.assertNotIn("management.sock", repr(client))
        method, path, body, headers = client.connection.request_call or ()
        self.assertEqual((method, path), ("POST", "/api/v1/agents/register"))
        self.assertNotIn("Authorization", headers)
        self.assertNotIn(TOKEN.encode(), body)
        self.assertTrue(client.connection.closed)

    def test_management_error_does_not_include_response_body(self) -> None:
        client = StubManagementClient(
            FakeResponse(500, f"{TOKEN}\n{PROMPT}".encode("utf-8"))
        )
        with self.assertRaises(ManagementError) as raised:
            client.register(
                RegistrationRequest(
                    agent_name="demo-agent",
                    cgroup_path="/sys/fs/cgroup/agentshield/demo/leaf",
                )
            )
        rendered = repr(raised.exception) + str(raised.exception)
        self.assertNotIn(TOKEN, rendered)
        self.assertNotIn(PROMPT, rendered)

    def test_redirect_is_not_followed(self) -> None:
        client = StubManagementClient(FakeResponse(307, b'{"location":"remote"}'))
        with self.assertRaises(ManagementError):
            client.register(
                RegistrationRequest(
                    agent_name="demo-agent",
                    cgroup_path="/sys/fs/cgroup/agentshield/demo/leaf",
                )
            )
        self.assertEqual(client.connection.request_call[1], "/api/v1/agents/register")


if __name__ == "__main__":
    unittest.main()
