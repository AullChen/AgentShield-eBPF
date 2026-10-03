"""Real Linux-only stopped workload fixture for the managed Core entry.

The trusted parent holds a new leaf FD, registers through supervisor.py, and
passes only checkpoint credentials over an anonymous pipe. The child drops to
UID/GID 65534, sends a real SDK checkpoint, then execs a bounded /bin/sleep.
This fixture must only run in the dedicated VM described in local-docs.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import sys
import time

REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY / "sandbox"))
sys.path.insert(0, str(REPOSITORY / "sdk" / "python"))

from supervisor import AgentCredentials, ManagementClient, Registration, RegistrationRequest, supervise
from agentshield import IngestClient


class StoppedFixture:
    def __init__(self, path: Path, ingest_url: str) -> None:
        self.path = path
        self.ingest_url = ingest_url
        self.fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.identity = os.fstat(self.fd)
        self.read_pipe, self.write_pipe = os.pipe()
        self.status: int | None = None
        self.pid = os.fork()
        if self.pid == 0:
            try:
                os.close(self.write_pipe)
                self._write("cgroup.procs", str(os.getpid()))
                os.setgroups([])
                os.setgid(65534)
                os.setuid(65534)
                os.kill(os.getpid(), signal.SIGSTOP)
                body = bytearray()
                while len(body) <= 4096:
                    chunk = os.read(self.read_pipe, 4096 - len(body) + 1)
                    if not chunk:
                        break
                    body.extend(chunk)
                if not body or len(body) > 4096:
                    os._exit(125)
                credentials = json.loads(body)
                client = IngestClient(self.ingest_url, credentials["run_id"], credentials["ingest_token"])
                client.checkpoint("tool_started", tool_name="sleep", summary="managed acceptance sleep attempt")
                os.execv("/bin/sleep", ["sleep", "20"])
            except BaseException:
                os._exit(125)
        os.close(self.read_pipe)
        waited, status = os.waitpid(self.pid, os.WUNTRACED)
        if waited != self.pid or not os.WIFSTOPPED(status):
            os.close(self.write_pipe)
            os.close(self.fd)
            raise RuntimeError("fixture did not reach stopped state")
        self.is_prepared = True
        self.registration_request = RegistrationRequest(agent_name="managed-runtime-fixture", cgroup_path=str(path), root_pid=self.pid)

    def _check_identity(self) -> None:
        if not os.path.samestat(self.identity, os.fstat(self.fd)) or not os.path.samestat(self.identity, os.stat(self.path, follow_symlinks=False)):
            raise RuntimeError("held fixture cgroup changed identity")

    def _write(self, name: str, value: str) -> None:
        self._check_identity()
        descriptor = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        try:
            os.write(descriptor, value.encode())
        finally:
            os.close(descriptor)

    def confirms_registration(self, registration: Registration) -> bool:
        self._check_identity()
        return registration.cgroup_path == str(self.path) and registration.cgroup_id == str(self.identity.st_ino) and registration.scope_mode == "leaf_exact"

    def confirm_stopped(self) -> None:
        self._check_identity()
        status = Path(f"/proc/{self.pid}/status").read_text()
        if not any(line.startswith("State:") and "T" in line for line in status.splitlines()):
            raise RuntimeError("fixture no longer stopped")
        membership = Path(f"/proc/{self.pid}/cgroup").read_text()
        relative = str(self.path.relative_to("/sys/fs/cgroup"))
        if f"0::/{relative}\n" not in membership:
            raise RuntimeError("fixture escaped held leaf")

    def start(self, credentials: AgentCredentials) -> None:
        self.confirm_stopped()
        body = json.dumps({"run_id": credentials.run_id, "ingest_token": credentials.ingest_token}).encode()
        if len(body) > 4096:
            raise RuntimeError("fixture credentials exceeded pipe limit")
        os.write(self.write_pipe, body)
        os.close(self.write_pipe)
        self.write_pipe = -1
        os.kill(self.pid, signal.SIGCONT)

    def wait_for_scope_exit(self, timeout: float | None = None) -> int:
        deadline = time.monotonic() + (60 if timeout is None else timeout)
        while time.monotonic() < deadline:
            self._check_identity()
            if self.status is None:
                waited, status = os.waitpid(self.pid, os.WNOHANG)
                if waited:
                    self.status = status
            descriptor = os.open("cgroup.events", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.fd)
            try:
                events = os.read(descriptor, 4096).decode()
            finally:
                os.close(descriptor)
            if self.status is not None and "populated 0" in events.splitlines():
                return os.waitstatus_to_exitcode(self.status)
            time.sleep(0.02)
        raise TimeoutError("fixture scope exit was not confirmed")

    def terminate(self) -> None:
        self.kill()

    def kill(self) -> None:
        self._write("cgroup.kill", "1")

    def close(self) -> None:
        if self.write_pipe >= 0:
            os.close(self.write_pipe)
            self.write_pipe = -1
        os.close(self.fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--isolated-vm", action="store_true", required=True)
    parser.add_argument("--management-socket", required=True)
    parser.add_argument("--ingest-url", default="http://127.0.0.1:8081")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("fixture requires root on the dedicated Linux VM")
    path = Path(f"/sys/fs/cgroup/agentshield-managed-fixture-{os.getpid()}")
    path.mkdir(mode=0o700)
    task: StoppedFixture | None = None
    try:
        task = StoppedFixture(path, args.ingest_url)
        result = supervise(ManagementClient(args.management_socket), task, ingest_base_url=args.ingest_url)
        print(json.dumps({"run_id": result.run_id, "exit_code": result.exit_code, "status": result.finish.status}))
        # With the supplied contain policy, the actual cgroup.kill must end
        # sleep by SIGKILL. Other exits never count as containment acceptance.
        return 0 if result.exit_code == -signal.SIGKILL else 1
    finally:
        if task is not None:
            try:
                task.kill()
                task.wait_for_scope_exit(5)
            finally:
                task.close()
        path.rmdir()


if __name__ == "__main__":
    raise SystemExit(main())
