"""mitmproxy flow capture for Java/OkHttp apps."""
from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path
from threading import Thread

from rich.console import Console

_URL_RE = __import__("re").compile(r'https?://([^/\s?#]+)(/[^\s?#]*)?')


class MitmproxyTap:
    """Run mitmdump transparently and collect flows to a file."""

    def __init__(self, device: str, host: str, port: int, console: Console) -> None:
        self.device = device
        self.host = host
        self.port = port
        self.console = console

    def capture(self, timeout: int = 120) -> list[dict]:
        """Start mitmdump, wait timeout, parse captured flows."""
        flow_file = Path(tempfile.mktemp(suffix=".flows"))

        addon_script = self._write_addon(flow_file)

        cmd = [
            "mitmdump",
            "--listen-host", self.host,
            "--listen-port", str(self.port),
            "--ssl-insecure",
            "-s", str(addon_script),
            "--quiet",
        ]

        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.console.print(f"  [yellow]→[/yellow] mitmdump listening on {self.host}:{self.port}")

        time.sleep(timeout)
        proc.terminate()
        proc.wait(timeout=10)

        if not flow_file.exists():
            return []

        return self._parse_flows(flow_file)

    def _write_addon(self, flow_file: Path) -> Path:
        script = Path(tempfile.mktemp(suffix=".py"))
        script.write_text(f"""
import json
from mitmproxy import http

FLOW_FILE = {str(flow_file)!r}

def request(flow: http.HTTPFlow) -> None:
    entry = {{
        "method": flow.request.method,
        "url": flow.request.pretty_url,
        "headers": dict(flow.request.headers),
        "body": flow.request.get_content(strict=False).decode("utf-8", errors="replace"),
    }}
    with open(FLOW_FILE, "a") as f:
        f.write(json.dumps(entry) + "\\n")

def response(flow: http.HTTPFlow) -> None:
    if not flow.response:
        return
    entry = {{
        "url": flow.request.pretty_url,
        "status": flow.response.status_code,
        "response_body": flow.response.get_content(strict=False).decode("utf-8", errors="replace")[:16384],
    }}
    with open(FLOW_FILE, "a") as f:
        f.write(json.dumps(entry) + "\\n")
""")
        return script

    def _parse_flows(self, flow_file: Path) -> list[dict]:
        endpoints: list[dict] = []
        seen: set[str] = set()

        for line in flow_file.read_text().splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            url = entry.get("url", "")
            m = _URL_RE.match(url)
            if not m:
                continue

            host = m.group(1)
            path = m.group(2) or "/"
            key = f"{entry.get('method','?')}:{host}{path}"

            if key in seen:
                continue
            seen.add(key)

            headers = entry.get("headers", {})
            auth = bool(headers.get("Authorization") or headers.get("authorization"))
            body_str = entry.get("body", "")

            ep: dict = {
                "method": entry.get("method", "GET").upper(),
                "host": host,
                "path": path,
                "source": "mitmproxy",
                "auth": auth,
            }

            if body_str:
                try:
                    ep["request_body"] = json.loads(body_str)
                except (json.JSONDecodeError, ValueError):
                    pass

            resp_str = entry.get("response_body", "")
            if resp_str:
                try:
                    ep["response_body"] = json.loads(resp_str)
                except (json.JSONDecodeError, ValueError):
                    pass

            endpoints.append(ep)

        return endpoints
