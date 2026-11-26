#!/usr/bin/env python3
"""Exercise the production x86_64 image without credentials or persistent session data."""
from __future__ import annotations

import json
import os
import socket
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request


IMAGE = os.environ.get("WRAPPER_PRODUCTION_IMAGE", "wrapper-v2:private-ci")
CONTAINER = os.environ.get("WRAPPER_PRODUCTION_CONTAINER", "wrapper-private-smoke")
SESSION_PATH = "/srv/wrapper/rootfs/data/data/com.apple.android.music/files"
ROOTFS_TMP = "/srv/wrapper/rootfs/tmp"
EXPECTED_PROFILE = "apple-music-1109-x86_64"
# Isolated smoke-test credential; it is not an Apple Account or deployment secret.
TEST_API_TOKEN = "production-smoke-" + ("a" * 64)


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["docker", *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if check and result.returncode:
        raise RuntimeError(
            f"docker {args[0]} failed ({result.returncode})\n"
            f"stdout: {result.stdout[-4000:]}\n"
            f"stderr: {result.stderr[-4000:]}"
        )
    return result


def reserve_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request(
    port: int,
    path: str,
    timeout_seconds: int = 5,
    token: str | None = TEST_API_TOKEN,
) -> tuple[int, dict]:
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        method="GET",
        headers=headers,
    )
    try:
        response = urllib.request.urlopen(req, timeout=timeout_seconds)
    except urllib.error.HTTPError as error:
        response = error
    raw = response.read()
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"{path} returned a non-JSON response (HTTP {response.status})") from error
    if not isinstance(payload, dict):
        raise RuntimeError(f"{path} returned an unexpected JSON shape")
    return response.status, payload


def read_process_status(pid: int) -> dict[str, str]:
    try:
        entries = {}
        for line in Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                entries[key] = value.strip()
        return entries
    except (OSError, UnicodeError) as error:
        raise RuntimeError(f"cannot inspect process security state for PID {pid}") from error


def check_process_capabilities() -> None:
    inspected = json.loads(docker("inspect", CONTAINER).stdout)[0]
    wrapper_pid = int(inspected["State"]["Pid"])
    violations: list[str] = []

    def check_unprivileged(pid: int, name: str, require_no_new_privs: bool = False) -> None:
        status = read_process_status(pid)
        uid = status.get("Uid", "").split()
        if not uid or uid[0] != "1000":
            violations.append(f"{name}: expected UID 1000")
        for field in ("CapEff", "CapPrm", "CapAmb"):
            raw = status.get(field, "0")
            try:
                capabilities = int(raw, 16)
            except ValueError:
                violations.append(f"{name}: invalid {field} value")
                continue
            if capabilities:
                violations.append(f"{name}: {field}={raw} (must be zero)")
        if require_no_new_privs and status.get("NoNewPrivs") != "1":
            violations.append(f"{name}: NoNewPrivs is not enabled")

    # Docker's CapAdd is required by the launcher executable, not by the HTTP server.
    check_unprivileged(wrapper_pid, "wrapperd")

    processes = docker("top", CONTAINER, "-eo", "pid,comm").stdout.splitlines()
    native_workers: list[tuple[int, str]] = []
    launchers: list[tuple[int, str]] = []
    for line in processes:
        fields = line.split(None, 1)
        if len(fields) != 2 or not fields[0].isdigit():
            continue
        pid, command = int(fields[0]), fields[1].strip()
        if command == "worker-launch":
            launchers.append((pid, command))
        elif command.startswith("apple-music"):
            native_workers.append((pid, command))

    for pid, command in launchers:
        check_unprivileged(pid, command)
    if not native_workers:
        violations.append("native Apple worker was not visible in the container process table")
    for pid, command in native_workers:
        check_unprivileged(pid, command, require_no_new_privs=True)

    if violations:
        raise RuntimeError("process privilege audit failed: " + "; ".join(violations))

def check_container_policy() -> None:
    inspected = json.loads(docker("inspect", CONTAINER).stdout)[0]
    config = inspected["Config"]
    host = inspected["HostConfig"]

    if config.get("User") != "1000:1000":
        raise RuntimeError("production container is not configured for UID/GID 1000")
    if not host.get("ReadonlyRootfs"):
        raise RuntimeError("production container root filesystem is writable")
    if "ALL" not in (host.get("CapDrop") or []):
        raise RuntimeError("production container does not drop all capabilities")
    # Docker Engine inspect may return capability names with the Linux CAP_ prefix.
    # Normalize that API representation while preserving the strict allow-list.
    cap_add = {
        capability.removeprefix("CAP_")
        for capability in (host.get("CapAdd") or [])
    }
    if cap_add != {"SYS_ADMIN", "SYS_CHROOT"}:
        raise RuntimeError(f"unexpected production capabilities: {sorted(cap_add)}")
    if "apparmor:unconfined" not in (host.get("SecurityOpt") or []):
        raise RuntimeError("production container is missing its documented AppArmor setting")

    bindings = (host.get("PortBindings") or {}).get("80/tcp") or []
    if not bindings or any(binding.get("HostIp") != "127.0.0.1" for binding in bindings):
        raise RuntimeError("production HTTP port is not bound exclusively to loopback")

    tmpfs_destinations = set((host.get("Tmpfs") or {}).keys())
    if not {ROOTFS_TMP, SESSION_PATH}.issubset(tmpfs_destinations):
        raise RuntimeError("ephemeral tmpfs mounts for rootfs tmp and session data are missing")


def main() -> None:
    if docker("image", "inspect", IMAGE, check=False).returncode:
        raise RuntimeError(f"production image is not present locally: {IMAGE}")

    port = reserve_port()
    created = False
    try:
        docker(
            "run", "--detach", "--name", CONTAINER,
            "--init",
            "--read-only",
            "--cap-drop=ALL",
            "--cap-add=SYS_ADMIN",
            "--cap-add=SYS_CHROOT",
            "--security-opt=apparmor:unconfined",
            "--env", f"WRAPPER_API_TOKEN={TEST_API_TOKEN}",
            "--user=1000:1000",
            "--tmpfs", f"{ROOTFS_TMP}:rw,nosuid,nodev,mode=1777",
            "--tmpfs", f"{SESSION_PATH}:rw,nosuid,nodev,mode=0770,uid=1000,gid=1000",
            "--publish", f"127.0.0.1:{port}:80",
            IMAGE,
        )
        created = True
        check_container_policy()

        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            state = docker(
                "inspect", "--format", "{{.State.Running}}", CONTAINER, check=False
            )
            if state.returncode == 0 and state.stdout.strip() == "true":
                try:
                    status, health = request(port, "/health", timeout_seconds=2, token=None)
                    if status == 200 and health.get("status") == "ok":
                        break
                except (OSError, RuntimeError, urllib.error.URLError):
                    pass
            time.sleep(0.5)
        else:
            raise RuntimeError("production image did not become healthy within 90 seconds")

        # Exercise the configured Bearer middleware in the actual production image.
        status, denied = request(port, "/info", token=None)
        if status != 401 or (denied.get("error") or {}).get("code") != "unauthorized":
            raise RuntimeError("/info did not reject a request without a Bearer token")
        status, denied = request(port, "/info", token="invalid-smoke-token")
        if status != 401 or (denied.get("error") or {}).get("code") != "unauthorized":
            raise RuntimeError("/info did not reject an invalid Bearer token")
        check_process_capabilities()

        status, health = request(port, "/health", token=None)
        if status != 200 or health.get("status") != "ok":
            raise RuntimeError("/health must remain publicly accessible without a Bearer token")

        status, info = request(port, "/info")
        if status != 200:
            raise RuntimeError(f"authenticated /info returned HTTP {status}")
        if info.get("architecture") != "x86_64" or info.get("profile") != EXPECTED_PROFILE:
            raise RuntimeError("production image reports an unexpected runtime profile")
        if info.get("context_supported") is not True:
            raise RuntimeError("production image does not report context support")

        # An empty tmpfs session directory prevents access to any real account
        # state. This request boots the actual native worker but does not log in.
        status, session = request(port, "/session", timeout_seconds=150)
        if status == 200:
            if not isinstance(session.get("state"), str) or session["state"] != "logged_out":
                raise RuntimeError("fresh ephemeral session did not remain logged out")
        elif status == 503:
            code = (session.get("error") or {}).get("code")
            if code not in {"no_cached_session", "session_expired"}:
                raise RuntimeError(f"native worker session check failed: {code or 'unknown_error'}")
        else:
            raise RuntimeError(f"/session returned unexpected HTTP status {status}")

        status, health = request(port, "/health", token=None)
        if status != 200 or health.get("status") != "ok":
            raise RuntimeError("production container stopped responding after native-worker startup")

        running = docker("inspect", "--format", "{{.State.Running}}", CONTAINER)
        if running.stdout.strip() != "true":
            raise RuntimeError("production container exited during the native-worker smoke test")

        print("Production x86_64 image smoke test passed.")
        print("Verified: runtime profile, loopback binding, read-only rootfs, and least-privilege capabilities.")
        print("Verified: public health, Bearer rejection/acceptance, ephemeral session storage,")
        print("and native-worker startup without Apple Account credentials.")
    finally:
        if created:
            docker("rm", "--force", CONTAINER, check=False)


if __name__ == "__main__":
    main()
