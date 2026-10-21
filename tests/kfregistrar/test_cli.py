"""Run the installed service entry point on actual loopback HTTP sockets."""
import json
import os
from uuid import uuid4
import socket
import subprocess
import time
from urllib.request import urlopen


def port():
    """Reserve an available loopback port briefly for a local subprocess test."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_installed_cli_runs_its_own_dual_http_service(tmp_path):
    """Launch the installed binary with the additive flags and probe both APIs.

    Parameters:
        tmp_path: private home directory for the subprocess's real identity/store.
    """
    internal, external = port(), port()
    while external == internal:
        external = port()
    env = {**os.environ, "HOME": str(tmp_path),
           "KLI_KEYSTORE_PASSCODE": "0123456789abcdefghijk"}
    log = tmp_path / "registrar.log"
    with log.open("wb") as output:
        proc = subprocess.Popen([
            "kf-registrar", "start", "--name", "cli-parity", "--base", "cli-" + uuid4().hex,
            "--alias", "registrar", "--bootport", str(internal), "--http", str(external),
            "--publisher", "explicit-unused-test-role", "--full-evidence", "--no-prompt"],
            env=env, stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 15
            for endpoint in (internal, external):
                while True:
                    if proc.poll() is not None:
                        raise AssertionError(log.read_text())
                    try:
                        with urlopen(f"http://127.0.0.1:{endpoint}/health", timeout=.3) as response:
                            assert json.load(response) == {"status": "ok"}
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise AssertionError(log.read_text())
                        time.sleep(.05)
        finally:
            proc.terminate()
            proc.wait(timeout=10)
