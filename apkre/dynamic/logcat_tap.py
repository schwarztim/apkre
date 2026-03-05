"""Flutter Dio logcat interceptor — zero-setup for debug Flutter builds."""
from __future__ import annotations

import re
import subprocess
import time
from threading import Thread

from rich.console import Console
from rich.live import Live
from rich.table import Table

# Dio log format (flutter tag):
#   [INFO] flutter: *** Request ***
#   [INFO] flutter: uri: https://api.bambulab.com/v1/iot-service/api/user/bind
#   [INFO] flutter: method: GET
#   [INFO] flutter: responseBody: {...}
_ANSI_RE  = re.compile(r'\x1b\[[0-9;]*m')
_URI_RE   = re.compile(r'uri:\s*(https?://\S+)')
_METHOD_RE = re.compile(r'method:\s*(\w+)')
_STATUS_RE = re.compile(r'statusCode:\s*(\d+)')
_REQ_RE   = re.compile(r'requestBody:\s*(\{.*\}|\[.*\])')
_RESP_RE  = re.compile(r'responseBody:\s*(\{.*\}|\[.*\])')
_AUTH_RE  = re.compile(r'Authorization["\s:]+([^\s,\]]+)')
# Broader header regex for Dio LogInterceptor(requestHeader: true) dumps
_HEADER_AUTH_RE = re.compile(
    r'(?:authorization|x-token|x-api-key|x-auth-token|bearer)\s*:\s*(\S+)',
    re.IGNORECASE,
)
_URL_RE   = re.compile(r'https?://([^/\s?#]+)(/[^\s?#]*)?\??([^\s#]*)?')

# Telemetry/analytics hosts to ignore — they flood the capture with noise
_NOISE_HOSTS = {
    "event.bblmw.com",
    "ip-api.com",
    "firebaseinstallations.googleapis.com",
    "firebaselogging-pa.googleapis.com",
    "app-measurement.com",
    "graph.facebook.com",
    "analytics.google.com",
    "crashlytics.com",
    "sentry.io",
}


class LogcatTap:
    """Parse adb logcat flutter tag for Dio-logged HTTP traffic."""

    def __init__(self, device: str, console: Console) -> None:
        self.device = device
        self.console = console
        self._lines: list[str] = []
        self._stop_flag: list[bool] = [False]
        self._thread: Thread | None = None

    def start(self) -> None:
        """Start non-blocking background logcat capture."""
        self._lines = []
        self._stop_flag = [False]

        subprocess.run(
            ["adb", "-s", self.device, "logcat", "-c"],
            capture_output=True, timeout=10,
        )

        def reader():
            cmd = ["adb", "-s", self.device, "logcat", "-s", "flutter:*", "-v", "raw"]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            try:
                while not self._stop_flag[0]:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    self._lines.append(line)
            finally:
                proc.terminate()

        self._thread = Thread(target=reader, daemon=True)
        self._thread.start()

    def stop(self) -> list[dict]:
        """Stop background capture and return parsed endpoints."""
        self._stop_flag[0] = True
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        return self._parse_lines(self._lines)

    def capture(self, timeout: int = 60, interactive: bool = False) -> list[dict]:
        """Stream logcat for `timeout` seconds, parse Dio log entries.

        If interactive=True, shows a live table of endpoints as they're discovered
        and waits for the user to press Enter (or timeout) instead of a fixed timer.
        """
        lines: list[str] = []
        stop_flag = [False]

        # Clear logcat buffer before starting to avoid stale data
        subprocess.run(
            ["adb", "-s", self.device, "logcat", "-c"],
            capture_output=True, timeout=10,
        )

        def reader():
            cmd = ["adb", "-s", self.device, "logcat", "-s", "flutter:*", "-v", "raw"]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            try:
                while not stop_flag[0]:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    lines.append(line)
            finally:
                proc.terminate()

        t = Thread(target=reader, daemon=True)
        t.start()

        if interactive:
            self._interactive_capture(lines, timeout)
        else:
            deadline = time.time() + timeout
            while time.time() < deadline:
                time.sleep(0.5)

        stop_flag[0] = True
        t.join(timeout=5)

        endpoints = self._parse_lines(lines)
        return endpoints

    def _interactive_capture(self, lines: list[str], timeout: int) -> None:
        """Show live endpoint count and wait for user signal or timeout."""
        last_count = 0
        deadline = time.time() + timeout
        self.console.print("  [bold yellow]Interact with the app now. Press Ctrl+C when done.[/bold yellow]")
        try:
            while time.time() < deadline:
                time.sleep(1)
                # Count unique URIs so far
                uri_count = sum(1 for l in lines if "uri:" in l.lower() or "uri:" in _ANSI_RE.sub('', l).lower())
                if uri_count != last_count:
                    parsed = self._parse_lines(lines)
                    self.console.print(
                        f"  [dim]... {len(parsed)} unique endpoints captured "
                        f"({len(lines)} raw lines)[/dim]",
                        highlight=False,
                    )
                    last_count = uri_count
        except KeyboardInterrupt:
            self.console.print("  [green]Capture stopped by user.[/green]")

    def _parse_lines(self, lines: list[str]) -> list[dict]:
        import json

        # Track endpoints by (method, host, path) for dedup and response matching
        seen: dict[tuple[str, str, str], dict] = {}
        pending_uri: dict | None = None
        # Also track the last key for attaching status/body/auth after method line
        last_key: tuple[str, str, str] | None = None

        for raw_line in lines:
            line = _ANSI_RE.sub('', raw_line).strip()
            # Strip box-drawing and emoji decorators
            line = re.sub(r'[│┌└├┄─]+', '', line).strip()
            line = re.sub(r'[💡⛔🔶🟢🔴]\s*', '', line).strip()

            m = _URI_RE.search(line)
            if m:
                url = m.group(1)
                parsed = _parse_url(url)
                if parsed:
                    pending_uri = parsed
                continue

            m = _METHOD_RE.search(line)
            if m and pending_uri:
                method = m.group(1).upper()
                key = (method, pending_uri["host"], pending_uri["path"])
                if key not in seen:
                    ep = {
                        **pending_uri,
                        "method": method,
                        "source": "logcat-dio",
                        "auth": False,
                    }
                    seen[key] = ep
                last_key = key
                pending_uri = None
                continue

            m = _STATUS_RE.search(line)
            if m:
                k = last_key or (pending_uri and ("?", pending_uri["host"], pending_uri["path"]))
                if k and k in seen:
                    seen[k]["status"] = int(m.group(1))
                if pending_uri:
                    pending_uri = None
                continue

            m = _REQ_RE.search(line)
            if m and last_key and last_key in seen:
                try:
                    seen[last_key]["request_body"] = json.loads(m.group(1))
                except (json.JSONDecodeError, ValueError):
                    pass
                continue

            m = _RESP_RE.search(line)
            if m and last_key and last_key in seen:
                try:
                    seen[last_key]["response_body"] = json.loads(m.group(1))
                except (json.JSONDecodeError, ValueError):
                    pass
                continue

            # Primary auth capture is via Frida SSL hooks; logcat is a fallback
            # for apps that configure Dio LogInterceptor(requestHeader: true)
            m = _AUTH_RE.search(line) or _HEADER_AUTH_RE.search(line)
            if m and last_key and last_key in seen:
                seen[last_key]["auth"] = True
                seen[last_key]["token"] = m.group(1)

        return list(seen.values())


def _parse_url(url: str) -> dict | None:
    m = _URL_RE.match(url)
    if not m:
        return None
    host = m.group(1)
    # Filter noise/telemetry hosts
    if host.lower() in _NOISE_HOSTS:
        return None
    path = m.group(2) or "/"
    query = m.group(3) or ""
    result = {"host": host, "path": path}
    if query:
        result["query"] = query
    return result
