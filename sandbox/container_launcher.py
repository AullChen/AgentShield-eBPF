"""Root-only Linux adapter: one offline container, one persistent exact leaf.

Only the trusted init runs before registration. Docker, the image, init binary,
approved project directory, and cgroup parent are trusted operator inputs.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import time

from supervisor import AgentCredentials, ManagementClient, Registration, RegistrationRequest, supervise


_IMAGE = re.compile(r"^(?:sha256:[0-9a-f]{64}|[^\s]+@sha256:[0-9a-f]{64})$")
_ID = re.compile(r"^[0-9a-f]{64}$")
_ENV = {"PATH", "LANG", "TZ", "TERM"}
_DOCKER_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root"}


def trusted_path(value: str, kind: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or str(path.resolve()) != str(path) or any(c in value for c in ",\x00\n"):
        raise ValueError("mount paths must be absolute, canonical, and contain no commas")
    info = path.stat()
    valid = {"directory": stat.S_ISDIR, "file": stat.S_ISREG, "socket": stat.S_ISSOCK}[kind]
    if not valid(info.st_mode):
        raise ValueError("invalid mount source type")
    return path


def create_arguments(image: str, project: Path, init: Path, gateway: Path) -> list[str]:
    if not _IMAGE.fullmatch(image):
        raise ValueError("use a locally installed immutable image ID/digest")
    return ["create", "--pull=never", "--interactive", "--network=none", "--read-only",
            "--user=65532:65532", "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--cgroupns=host", "--no-healthcheck", "--restart=no", "--workdir=/workspace",
            "--log-driver=json-file", "--log-opt=max-size=64k", "--log-opt=max-file=1",
            "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777", "--shm-size=1m",
            "--mount", f"type=bind,src={project},dst=/workspace,readonly,bind-recursive=disabled",
            "--mount", f"type=bind,src={init},dst=/agentshield/init,readonly",
            "--mount", f"type=bind,src={gateway},dst=/run/agentshield/gateway.sock,readonly",
            "--entrypoint=/agentshield/init", image]


class ContainerTask:
    def __init__(self, *, image: str, project: str, init: str, gateway: str,
                 cgroup_parent: str, command: list[str], timeout: int = 300,
                 memory: int = 512 << 20, pids: int = 64, cpu_quota: int = 50000) -> None:
        if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
            raise ValueError("requires root on the same Linux host as the local Docker engine")
        if not command or not command[0].startswith("/") or not 1 <= timeout <= 900:
            raise ValueError("absolute command and timeout of 1..900 seconds required")
        if not 32 << 20 <= memory <= 64 << 30 or not 16 <= pids <= 4096 or not 1000 <= cpu_quota <= 800000:
            raise ValueError("invalid resource budget")
        self.project = trusted_path(project, "directory")
        if self.project.stat().st_uid != 0 or self.project.stat().st_mode & 0o022:
            raise ValueError("use a private root-owned approved project copy")
        # Read-only mounts still permit connecting to host Unix sockets. The
        # operator must keep this approved copy stable until task completion.
        for directory, dirs, files in os.walk(self.project, followlinks=False):
            for name in dirs + files:
                mode = (Path(directory) / name).lstat().st_mode
                if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode)):
                    raise ValueError("approved project contains a host communication/device file")
                info = (Path(directory) / name).lstat()
                if not stat.S_ISLNK(mode) and (info.st_uid != 0 or mode & 0o022):
                    raise ValueError("approved project copy must not be writable by untrusted users")
        self.init = trusted_path(init, "file")
        self.gateway = trusted_path(gateway, "socket")
        parent = trusted_path(cgroup_parent, "directory")
        if not str(parent).startswith("/sys/fs/cgroup/") or parent.stat().st_uid != 0 or parent.stat().st_mode & 0o022:
            raise ValueError("requires a dedicated root-owned cgroup v2 parent")
        if self.project in (Path("/"), Path("/root"), Path("/home")) or any(part in {".ssh", ".aws", ".azure", ".config"} for part in self.project.parts):
            raise ValueError("do not mount a home or credential directory")
        if self.project == Path(os.path.expanduser("~")) or self.init.stat().st_uid != 0 or self.init.stat().st_mode & 0o022:
            raise ValueError("init must be root-owned and not group/world writable")
        gateway_parent = self.gateway.parent.stat()
        if self.gateway.stat().st_uid != 0 or gateway_parent.st_uid != 0 or gateway_parent.st_mode & 0o077:
            raise ValueError("gateway socket requires a root-only parent directory")
        self.command, self.timeout = command, timeout
        self.container_id, self.pid, self.start_time, self.fd = "", 0, "", -1
        self.attach = None
        self.leaf = parent / ("run-" + os.urandom(16).hex())
        self._request = None
        try:
            info = json.loads(self._docker("info", "--format={{json .SecurityOptions}}"))
            if any("rootless" in option or "userns" in option for option in info):
                raise ValueError("rootless/remapped engines are not supported by this adapter")
            image_info = json.loads(self._docker("image", "inspect", image))[0]["Config"]
            if image_info.get("Volumes") or any(item.split("=", 1)[0] not in _ENV for item in image_info.get("Env") or []):
                raise ValueError("image declares implicit volumes or non-whitelisted environment")
            if not {"cpu", "memory", "pids"}.issubset((parent / "cgroup.subtree_control").read_text().split()):
                raise ValueError("enable cpu, memory, pids controllers on the dedicated parent first")
            self.leaf.mkdir(mode=0o700)
            self.fd = os.open(self.leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            for name, value in (("memory.max", str(memory)), ("memory.swap.max", "0"),
                                ("pids.max", str(pids)), ("cpu.max", f"{cpu_quota} 100000")):
                self._write(name, value)
                if self._read(name).strip() != value:
                    raise RuntimeError("resource limit readback failed")
            self.container_id = self._docker(*create_arguments(image, self.project, self.init, self.gateway)).strip()
            if not _ID.fullmatch(self.container_id):
                raise RuntimeError("invalid container identity")
            self.attach = subprocess.Popen(self._argv("start", "--attach", "--interactive", self.container_id),
                                           stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                           close_fds=True, env=_DOCKER_ENV)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                state = self._state()
                if state["Running"] and "agentshield-init-ready\n" in self._docker("logs", self.container_id):
                    self.pid = int(state["Pid"])
                    break
                if state["Status"] == "exited":
                    raise RuntimeError("trusted init exited before preparation")
                time.sleep(0.05)
            if self.pid <= 0:
                raise RuntimeError("trusted init preparation timed out")
            self.start_time = self._pid_start()
            os.kill(self.pid, signal.SIGSTOP)
            self._wait_stopped()
            self._write("cgroup.procs", str(self.pid))
            self._request = RegistrationRequest("controlled-harness", str(self.leaf), self.container_id, self.pid)
            self.confirm_stopped()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _argv(*arguments: str) -> list[str]:
        # Ignore DOCKER_HOST/context, proxy variables, credential helpers, and
        # inherited descriptors. Only the local trusted engine is in scope.
        return ["/usr/bin/docker", "--host=unix:///var/run/docker.sock", *arguments]

    def _docker(self, *arguments: str) -> str:
        result = subprocess.run(self._argv(*arguments), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, env=_DOCKER_ENV, close_fds=True, timeout=10, check=True)
        if len(result.stdout) > 128 << 10:
            raise RuntimeError("Docker response exceeded limit")
        return result.stdout.decode("utf-8")

    def _state(self) -> dict:
        return json.loads(self._docker("inspect", "--format={{json .State}}", self.container_id))

    def _read(self, name: str) -> str:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.fd)
        with os.fdopen(fd) as source:
            return source.read(4096)

    def _write(self, name: str, value: str) -> None:
        fd = os.open(name, os.O_WRONLY | os.O_NOFOLLOW, dir_fd=self.fd)
        with os.fdopen(fd, "w") as target:
            target.write(value)

    def _pid_start(self) -> str:
        return Path(f"/proc/{self.pid}/stat").read_text().rsplit(")", 1)[1].split()[19]

    def _all_stopped(self) -> bool:
        statuses = list(Path(f"/proc/{self.pid}/task").glob("*/status"))
        return bool(statuses) and all(re.search(r"^State:\s+[Tt]\b", path.read_text(), re.M) for path in statuses)

    def _wait_stopped(self) -> None:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if self._all_stopped():
                return
            time.sleep(0.01)
        raise RuntimeError("init threads are not stopped")

    @property
    def is_prepared(self) -> bool:
        try:
            self.confirm_stopped()
            return True
        except (OSError, RuntimeError):
            return False

    @property
    def registration_request(self) -> RegistrationRequest:
        if self._request is None:
            raise RuntimeError("scope not prepared")
        return self._request

    def confirms_registration(self, registration: Registration) -> bool:
        self.confirm_stopped()
        return (registration.cgroup_path == str(self.leaf) and registration.scope_mode == "leaf_exact"
                and int(registration.cgroup_id) == os.fstat(self.fd).st_ino)

    def confirm_stopped(self) -> None:
        identity = os.fstat(self.fd)
        current = self.leaf.stat()
        membership = f"0::{str(self.leaf)[len('/sys/fs/cgroup'):]}\n"
        if ((identity.st_dev, identity.st_ino) != (current.st_dev, current.st_ino)
                or self._pid_start() != self.start_time or not self._all_stopped()
                or Path(f"/proc/{self.pid}/cgroup").read_text() != membership
                or self._read("cgroup.procs").split() != [str(self.pid)]
                or os.readlink(f"/proc/{self.pid}/ns/cgroup") != os.readlink("/proc/self/ns/cgroup")):
            raise RuntimeError("prepared task identity/state changed")

    def start(self, credentials: AgentCredentials) -> None:
        self.confirm_stopped()
        envelope = json.dumps({"run_id": credentials.run_id, "ingest_token": credentials.ingest_token,
                               "command": self.command, "timeout_seconds": self.timeout, "environment": {}}).encode()
        if len(envelope) > 16 << 10:
            raise ValueError("launch envelope exceeds limit")
        assert self.attach is not None and self.attach.stdin is not None
        self.attach.stdin.write(envelope)
        self.attach.stdin.close()
        os.kill(self.pid, signal.SIGCONT)

    def wait_for_scope_exit(self, timeout: float | None = None) -> int:
        deadline = time.monotonic() + (self.timeout + 10 if timeout is None else timeout)
        while time.monotonic() < deadline:
            state = self._state()
            if not state["Running"] and state["Status"] == "exited" and "populated 0" in self._read("cgroup.events"):
                return int(state["ExitCode"])
            time.sleep(0.05)
        raise TimeoutError("container root and held exact leaf have not exited")

    def terminate(self) -> None:
        if self.container_id:
            self._docker("kill", "--signal=TERM", self.container_id)

    def kill(self) -> None:
        if self.fd >= 0:
            self._write("cgroup.kill", "1")
        if self.container_id:
            self._docker("kill", "--signal=KILL", self.container_id)

    def close(self) -> None:
        # Delete only the leaf created by this instance, and only when empty.
        try:
            self.kill()
        except (OSError, RuntimeError, subprocess.SubprocessError):
            pass
        if self.attach is not None:
            if self.attach.stdin is not None and not self.attach.stdin.closed:
                self.attach.stdin.close()
            try:
                self.attach.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.attach.kill()
                self.attach.wait(timeout=5)
        if self.container_id:
            try:
                self._docker("rm", "--force", self.container_id)
            except (OSError, RuntimeError, subprocess.SubprocessError):
                pass
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1
            try:
                self.leaf.rmdir()
            except OSError:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("image", "project", "init", "gateway", "cgroup-parent", "management-socket"):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    task = None
    try:
        task = ContainerTask(image=args.image, project=args.project, init=args.init, gateway=args.gateway,
                             cgroup_parent=args.cgroup_parent, command=command, timeout=args.timeout)
        result = supervise(ManagementClient(args.management_socket), task, ingest_base_url="http://127.0.0.1:18181")
        print(json.dumps({"run_id": result.run_id, "exit_code": result.exit_code}))
        return result.exit_code if result.exit_code >= 0 else 1
    except (Exception, KeyboardInterrupt):
        print("controlled launch failed; no credentials or request bodies are logged", file=__import__("sys").stderr)
        return 1
    finally:
        if task is not None:
            task.close()


if __name__ == "__main__":
    raise SystemExit(main())
