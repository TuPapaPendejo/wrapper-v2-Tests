#!/usr/bin/env python3
"""Run Wrapper's real HTTP service inside a disposable Docker image with a mock worker."""
import json
import os
import socket
import subprocess
import time
import unittest
import urllib.error
import urllib.request
import uuid


TOKEN = "synthetic-container-token-" + ("a" * 64)
IMAGE = os.environ.get("WRAPPER_SYNTHETIC_IMAGE", "wrapper-v2:synthetic-ci")


def docker(*args, check=True):
    return subprocess.run(
        ["docker", *args],
        check=check,
        capture_output=True,
        text=True,
    )


def request(port, method, path, payload=None, token=TOKEN):
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=data,
        method=method,
        headers=headers,
    )
    try:
        response = urllib.request.urlopen(req, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    return response.status, json.loads(response.read())


class SyntheticContainerSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            cls.port = sock.getsockname()[1]
        cls.name = "wrapper-synthetic-" + uuid.uuid4().hex[:12]
        result = docker(
            "run", "-d", "--name", cls.name,
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--tmpfs", "/tmp:rw,nosuid,nodev,mode=1777",
            "--user", "1000:1000",
            "-p", f"127.0.0.1:{cls.port}:80",
            "-e", f"WRAPPER_API_TOKEN={TOKEN}",
            "-e", "WRAPPER_2FA_TIMEOUT_SECONDS=5",
            IMAGE,
        )
        cls.container_id = result.stdout.strip()
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if docker("inspect", "-f", "{{.State.Running}}", cls.name, check=False).returncode == 0:
                try:
                    if request(cls.port, "GET", "/health", token=None)[0] == 200:
                        break
                except (OSError, ValueError, urllib.error.URLError):
                    pass
            time.sleep(0.2)
        else:
            logs = docker("logs", cls.name, check=False).stdout
            raise RuntimeError("Synthetic Wrapper container failed to start:\n" + logs[-6000:])

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "name", None):
            docker("rm", "-f", cls.name, check=False)

    def test_container_security_and_api_contract(self):
        inspected = json.loads(docker("inspect", self.name).stdout)[0]
        self.assertEqual(inspected["Config"]["User"], "1000:1000")
        self.assertTrue(inspected["HostConfig"]["ReadonlyRootfs"])
        self.assertIn("ALL", inspected["HostConfig"]["CapDrop"])
        self.assertIn("no-new-privileges", inspected["HostConfig"]["SecurityOpt"])

        self.assertEqual(request(self.port, "GET", "/health", token=None)[0], 200)
        status, unauthorized = request(self.port, "GET", "/info", token=None)
        self.assertEqual(status, 401)
        self.assertEqual(unauthorized["error"]["code"], "unauthorized")
        self.assertEqual(request(self.port, "GET", "/info", token="wrong-token")[0], 401)

        status, info = request(self.port, "GET", "/info")
        self.assertEqual(status, 200)
        self.assertEqual(info["architecture"], "x86_64")
        self.assertEqual(info["profile"], "apple-music-1109-x86_64")
        self.assertTrue(info["context_supported"])

        status, session = request(self.port, "GET", "/session")
        self.assertEqual((status, session["state"]), (200, "logged_out"))

        status, challenge = request(
            self.port, "POST", "/session/login",
            {"username": "twofactor", "password": "synthetic-password"},
        )
        self.assertEqual(status, 202)
        self.assertEqual(challenge["kind"], "two_factor")
        self.assertEqual(request(self.port, "GET", "/session")[0], 503)
        status, pending = request(self.port, "GET", "/session/challenge")
        self.assertEqual((status, pending["challenge_id"]), (202, challenge["challenge_id"]))

        status, session = request(
            self.port, "POST", "/session/challenge",
            {"challenge_id": challenge["challenge_id"], "code": "123456"},
        )
        self.assertEqual((status, session["state"]), (200, "authenticated"))

        status, credentials = request(self.port, "GET", "/session/credentials")
        self.assertEqual(status, 200)
        self.assertEqual(credentials["dev_token"], "mock-developer-token")
        self.assertEqual(request(self.port, "GET", "/playback?adam_id=12345")[0], 200)

        status, context = request(
            self.port, "GET",
            "/context?adam_id=12345&key_uri=skd%3A%2F%2Fsynthetic",
        )
        self.assertEqual(status, 200)
        self.assertEqual(context["profile"], "apple-music-1109-x86_64")
        self.assertEqual(request(
            self.port, "GET",
            "/key?adamId=12345&uri=skd%3A%2F%2Fsynthetic",
        )[0], 200)

        self.assertEqual(request(self.port, "POST", "/session/close")[0], 200)
        self.assertEqual(request(self.port, "GET", "/session")[1]["state"], "logged_out")

        # Let a second challenge expire, then verify the lock and worker lifecycle recover.
        status, abandoned = request(
            self.port, "POST", "/session/login",
            {"username": "twofactor", "password": "synthetic-password"},
        )
        self.assertEqual(status, 202)
        time.sleep(6)
        self.assertEqual(request(self.port, "GET", "/session/challenge")[0], 404)
        status, state = request(self.port, "GET", "/session")
        self.assertEqual((status, state["state"]), (200, "logged_out"))

        status, logged_in = request(
            self.port, "POST", "/session/login",
            {"username": "mock-account", "password": "synthetic-password"},
        )
        self.assertEqual((status, logged_in["state"]), (200, "authenticated"))

        logs = docker("logs", self.name).stdout
        self.assertNotIn(TOKEN, logs)
        self.assertNotIn("synthetic-password", logs)
        self.assertNotIn("mock-developer-token", logs)


if __name__ == "__main__":
    unittest.main(verbosity=2)
