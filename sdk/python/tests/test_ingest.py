from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
from pathlib import Path
import sys
import threading
from typing import Callable, Iterator
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentshield import (  # noqa: E402
    IngestClient,
    IngestHTTPError,
    IngestProtocolError,
    IngestStateError,
    IngestTransportError,
)


RUN_ID = "8bbbc043619641aba8007a9f255b2665"
TOKEN = "sensitive-run-token.unsigned-example"
PROMPT = "private full prompt that must not escape"


def receipt_for(request: "RecordedRequest") -> tuple[int, dict[str, str], bytes]:
    payload = json.loads(request.body)
    response = {
        "checkpoint_id": f"checkpoint-{payload['sequence']}",
        "run_id": RUN_ID,
        "sequence": payload["sequence"],
        "idempotency_key": payload["idempotency_key"],
        "server_received_monotonic_ns": "101",
        "server_received_unix_ns": "201",
        "clock_calibration_error_ns": "1",
        "client_reported_unix_ns": payload["client_reported_unix_ns"],
        "type": payload["type"],
        "source": "agent_claim",
    }
    return 201, {"Content-Type": "application/json"}, json.dumps(response).encode()


class RecordedRequest:
    def __init__(self, path: str, headers: dict[str, str], body: bytes) -> None:
        self.path = path
        self.headers = headers
        self.body = body


Response = tuple[int, dict[str, str], bytes]
Responder = Response | Callable[[RecordedRequest], Response]


class Script:
    def __init__(self, responses: list[Responder]) -> None:
        self.responses = responses
        self.requests: list[RecordedRequest] = []
        self.lock = threading.Lock()

    def handle(self, request: RecordedRequest) -> Response:
        with self.lock:
            self.requests.append(request)
            if self.responses:
                response = self.responses.pop(0)
            else:
                response = receipt_for
        return response(request) if callable(response) else response


@contextmanager
def serve(script: Script) -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            recorded = RecordedRequest(
                self.path,
                {name: value for name, value in self.headers.items()},
                self.rfile.read(length),
            )
            status, headers, body = script.handle(recorded)
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class IngestClientTests(unittest.TestCase):
    def test_checkpoint_is_run_scoped_and_surface_is_write_only(self) -> None:
        script = Script([receipt_for])
        with serve(script) as url:
            client = IngestClient(url, RUN_ID, TOKEN)
            receipt = client.checkpoint(
                "tool_started",
                phase="execute",
                tool_name="python",
                summary="redacted summary",
                labels={"risk": "reviewed"},
                metadata={"adapter": "test"},
            )

        self.assertEqual(receipt["run_id"], RUN_ID)
        self.assertEqual(receipt["source"], "agent_claim")
        self.assertEqual(len(script.requests), 1)
        request = script.requests[0]
        self.assertEqual(
            request.path, f"/ingest/v1/runs/{RUN_ID}/checkpoints"
        )
        self.assertEqual(request.headers["Authorization"], f"Bearer {TOKEN}")
        self.assertEqual(request.headers["Content-Type"], "application/json")
        payload = json.loads(request.body)
        self.assertEqual(payload["sequence"], "1")
        self.assertTrue(payload["client_reported_unix_ns"].isdigit())
        self.assertNotIn("run_id", payload)
        self.assertNotIn("scope_cookie", payload)
        self.assertFalse(hasattr(client, "register"))
        self.assertFalse(hasattr(client, "finish"))
        self.assertNotIn(TOKEN, repr(client))
        self.assertIn("token=<redacted>", repr(client))

    def test_retryable_status_reuses_exact_request(self) -> None:
        script = Script(
            [
                (429, {"Content-Type": "text/plain", "Retry-After": "0"}, b"slow"),
                receipt_for,
                receipt_for,
            ]
        )
        with serve(script) as url:
            client = IngestClient(url, RUN_ID, TOKEN, max_retries=1, retry_backoff=0)
            first = client.checkpoint("llm_request", summary="redacted")
            second = client.checkpoint("llm_response", summary="redacted")

        self.assertEqual(script.requests[0].body, script.requests[1].body)
        self.assertEqual(
            script.requests[0].headers["Authorization"],
            script.requests[1].headers["Authorization"],
        )
        self.assertEqual(first["sequence"], "1")
        self.assertEqual(second["sequence"], "2")

    def test_malformed_retry_after_uses_bounded_backoff(self) -> None:
        script = Script(
            [
                (
                    503,
                    {"Content-Type": "text/plain", "Retry-After": "9" * 1000},
                    b"busy",
                ),
                receipt_for,
            ]
        )
        with serve(script) as url:
            client = IngestClient(url, RUN_ID, TOKEN, max_retries=1, retry_backoff=0)
            receipt = client.checkpoint("run_started")

        self.assertEqual(receipt["sequence"], "1")
        self.assertEqual(script.requests[0].body, script.requests[1].body)

    def test_redirect_is_not_followed_or_given_token(self) -> None:
        target = Script([])
        with serve(target) as target_url:
            redirect = Script(
                [
                    (
                        307,
                        {"Content-Type": "text/plain", "Location": target_url},
                        b"redirect",
                    )
                ]
            )
            with serve(redirect) as redirect_url:
                client = IngestClient(redirect_url, RUN_ID, TOKEN)
                with self.assertRaises(IngestHTTPError) as raised:
                    client.checkpoint("run_started")

        self.assertEqual(raised.exception.status, 307)
        self.assertEqual(target.requests, [])

    def test_error_and_logging_do_not_disclose_secrets(self) -> None:
        body = f"server echoed {TOKEN} and {PROMPT}".encode()
        script = Script([(500, {"Content-Type": "text/plain"}, body)])
        records: list[logging.LogRecord] = []

        class Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        capture = Capture()
        root = logging.getLogger()
        root.addHandler(capture)
        try:
            with serve(script) as url:
                client = IngestClient(url, RUN_ID, TOKEN, max_retries=0)
                with self.assertRaises(IngestHTTPError) as raised:
                    client.checkpoint("llm_request", summary=PROMPT)
        finally:
            root.removeHandler(capture)

        rendered = str(raised.exception) + repr(raised.exception) + repr(client)
        self.assertNotIn(TOKEN, rendered)
        self.assertNotIn(PROMPT, rendered)
        self.assertEqual(records, [])

    def test_invalid_success_can_retry_identical_pending_bytes(self) -> None:
        script = Script(
            [
                (201, {"Content-Type": "application/json"}, b"not-json"),
                receipt_for,
                receipt_for,
            ]
        )
        with serve(script) as url:
            client = IngestClient(url, RUN_ID, TOKEN)
            with self.assertRaises(IngestProtocolError):
                client.checkpoint("tool_finished", summary="redacted")
            with self.assertRaises(IngestStateError):
                client.checkpoint("run_finished")
            replay = client.retry_pending()
            following = client.checkpoint("run_finished")

        self.assertEqual(script.requests[0].body, script.requests[1].body)
        self.assertEqual(replay["sequence"], "1")
        self.assertEqual(following["sequence"], "2")

    def test_transport_error_is_sanitized_and_retains_exact_request(self) -> None:
        script = Script([receipt_for])

        class FailingConnection:
            def __init__(self) -> None:
                self.body = b""

            def request(
                self,
                _method: str,
                _path: str,
                body: bytes,
                headers: dict[str, str],
            ) -> None:
                del headers
                self.body = body
                raise OSError(f"transport exposed {TOKEN} and {PROMPT}")

            def close(self) -> None:
                return

        with serve(script) as url:
            client = IngestClient(url, RUN_ID, TOKEN)
            failing = FailingConnection()
            original_connection = client._connection
            client._connection = lambda: failing  # type: ignore[method-assign]
            with self.assertRaises(IngestTransportError) as raised:
                client.checkpoint("llm_request", summary=PROMPT)
            client._connection = original_connection  # type: ignore[method-assign]
            receipt = client.retry_pending()

        rendered = str(raised.exception) + repr(raised.exception)
        self.assertNotIn(TOKEN, rendered)
        self.assertNotIn(PROMPT, rendered)
        self.assertIsNone(raised.exception.__context__)
        self.assertEqual(failing.body, script.requests[0].body)
        self.assertEqual(receipt["sequence"], "1")

    def test_oversized_response_is_rejected_without_echo(self) -> None:
        secret_response = (TOKEN + PROMPT).encode() * 8192
        script = Script(
            [(201, {"Content-Type": "application/json"}, secret_response)]
        )
        with serve(script) as url:
            client = IngestClient(url, RUN_ID, TOKEN)
            with self.assertRaises(IngestProtocolError) as raised:
                client.checkpoint("run_started")

        rendered = str(raised.exception) + repr(raised.exception)
        self.assertNotIn(TOKEN, rendered)
        self.assertNotIn(PROMPT, rendered)
        self.assertIsNone(raised.exception.__context__)

    def test_invalid_server_clock_is_a_sanitized_protocol_error(self) -> None:
        def invalid_clock(request: RecordedRequest) -> Response:
            status, headers, body = receipt_for(request)
            receipt = json.loads(body)
            receipt["server_received_monotonic_ns"] = "9" * 60_000
            return status, headers, json.dumps(receipt).encode()

        script = Script([invalid_clock])
        with serve(script) as url:
            client = IngestClient(url, RUN_ID, TOKEN)
            with self.assertRaises(IngestProtocolError):
                client.checkpoint("run_started")

    def test_response_can_include_bounded_receipt_overhead(self) -> None:
        large = "x" * 1024
        labels = {f"label-{number:02d}": large for number in range(32)}
        metadata = {f"meta-{number:02d}": large for number in range(24)}
        script = Script([receipt_for])
        with serve(script) as url:
            client = IngestClient(url, RUN_ID, TOKEN)
            receipt = client.checkpoint(
                "llm_response",
                summary="s" * 4096,
                labels=labels,
                metadata=metadata,
            )
        self.assertEqual(receipt["sequence"], "1")
        self.assertLessEqual(len(script.requests[0].body), 64 << 10)

    def test_concurrent_callers_deliver_contiguous_sequences(self) -> None:
        script = Script([])
        with serve(script) as url:
            client = IngestClient(url, RUN_ID, TOKEN)
            barrier = threading.Barrier(17)

            def send(number: int) -> str:
                barrier.wait()
                return client.checkpoint(
                    "tool_started", metadata={"worker": str(number)}
                )["sequence"]

            with ThreadPoolExecutor(max_workers=16) as pool:
                futures = [pool.submit(send, number) for number in range(16)]
                barrier.wait()
                results = [future.result(timeout=5) for future in futures]

        delivered = [json.loads(request.body)["sequence"] for request in script.requests]
        self.assertEqual(delivered, [str(number) for number in range(1, 17)])
        self.assertEqual(sorted(map(int, results)), list(range(1, 17)))

    def test_input_validation_rejects_unsafe_configuration_and_payloads(self) -> None:
        invalid_urls = (
            "ftp://127.0.0.1",
            "http://example.com",
            "http://user:password@127.0.0.1",
            "http://127.0.0.1/prefix",
            "http://127.0.0.1/?token=secret",
        )
        for url in invalid_urls:
            with self.subTest(url=url), self.assertRaises(ValueError):
                IngestClient(url, RUN_ID, TOKEN)

        client = IngestClient("http://127.0.0.1:1", RUN_ID, TOKEN)
        with self.assertRaises(ValueError):
            client.checkpoint("unknown")
        with self.assertRaises(TypeError):
            client.checkpoint(42)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            client.checkpoint("run_started", idempotency_key="")
        with self.assertRaises(ValueError):
            client.checkpoint("llm_request", summary="x" * 4097)
        with self.assertRaises(ValueError):
            client.checkpoint("llm_request", labels={"": "value"})
        with self.assertRaises(ValueError):
            client.checkpoint("llm_request", labels={" ": "value"})
        with self.assertRaises(ValueError):
            client.checkpoint(
                "llm_request",
                labels={f"key-{number:02d}": "x" * 1024 for number in range(32)},
                metadata={f"key-{number:02d}": "x" * 1024 for number in range(32)},
            )
        with self.assertRaises(ValueError):
            IngestClient("http://127.0.0.1", RUN_ID, "token with whitespace")
        with self.assertRaises(ValueError):
            IngestClient("http://127.0.0.1", RUN_ID, "token-含非ASCII")


if __name__ == "__main__":
    unittest.main()
