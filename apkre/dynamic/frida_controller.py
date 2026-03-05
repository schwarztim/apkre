"""Frida spawn + inject controller — Frida 17.x compatible."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from threading import Event
from typing import Any

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False

from rich.console import Console

_AGENT_JS = Path(__file__).parent / "frida_agent.js"

_HTTP_REQUEST_RE = re.compile(
    r'^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(https?://[^\s]+|/[^\s]*)\s+HTTP',
    re.MULTILINE,
)
_AUTH_HEADER_RE = re.compile(
    r'^Authorization:\s*(.+)$', re.MULTILINE | re.IGNORECASE,
)
_URL_RE = re.compile(r'https?://([^/\s?#]+)(/[^\s?#]*)?')


class FridaController:
    """Spawn an Android app with Frida, inject SSL hooks, collect captured requests."""

    def __init__(self, device_serial: str, package: str, console: Console) -> None:
        self.device_serial = device_serial
        self.package = package
        self.console = console
        self._endpoints: list[dict] = []
        self._tokens: list[str] = []

    def capture(self, timeout: int = 300) -> list[dict]:
        if not FRIDA_AVAILABLE:
            self.console.print("[red]frida not installed. Run: pip install frida frida-tools[/red]")
            return []

        try:
            device = frida.get_device(self.device_serial)
        except frida.InvalidArgumentError:
            device = frida.get_usb_device()

        agent_js = _AGENT_JS.read_text()
        done = Event()
        http_buffer: dict[str, list[str]] = {}  # correlation: ssl_write chunks

        def on_message(message: dict, data: Any) -> None:
            if message.get("type") != "send":
                return
            payload = message.get("payload", {})
            mtype = payload.get("type", "")

            if mtype == "agent_ready":
                self.console.print("  [green]✓[/green] Frida agent ready")

            elif mtype == "hook_ok":
                self.console.print(f"  [green]✓[/green] Hooked: {payload.get('label')}")

            elif mtype in ("ssl_write", "ssl_read"):
                chunk = payload.get("data", "")
                self._parse_http_chunk(chunk, mtype)

            elif mtype == "okhttp":
                url = payload.get("url", "")
                parsed = _parse_url(url)
                if parsed:
                    self._endpoints.append({
                        **parsed,
                        "method": payload.get("method", "GET").upper(),
                        "source": "frida-okhttp",
                        "auth": False,
                        "status": payload.get("status"),
                    })

            elif mtype == "token":
                val = payload.get("value", "")
                if val and val not in self._tokens:
                    self._tokens.append(val)
                    self.console.print(f"  [yellow]★[/yellow] Token captured (len={len(val)})")

        pid = device.spawn([self.package])
        session = device.attach(pid)
        script = session.create_script(agent_js)
        script.on("message", on_message)
        script.load()
        device.resume(pid)

        self.console.print(f"  App spawned (pid={pid}), capturing for {timeout}s...")
        deadline = time.time() + timeout
        try:
            while time.time() < deadline:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            try:
                script.unload()
                session.detach()
            except Exception:
                pass

        return self._endpoints

    def _parse_http_chunk(self, chunk: str, direction: str) -> None:
        """Parse raw HTTP text captured from SSL buffer."""
        for m in _HTTP_REQUEST_RE.finditer(chunk):
            method = m.group(1)
            url_or_path = m.group(2)
            parsed = _parse_url(url_or_path) if url_or_path.startswith("http") else {"path": url_or_path, "host": ""}
            if not parsed:
                continue

            auth = bool(_AUTH_HEADER_RE.search(chunk))
            ep = {
                **parsed,
                "method": method,
                "source": "frida-ssl",
                "auth": auth,
            }

            # Try to extract auth token
            am = _AUTH_HEADER_RE.search(chunk)
            if am:
                token_val = am.group(1).strip()
                if token_val not in self._tokens:
                    self._tokens.append(token_val)

            # Try to extract request body (after blank line)
            body_m = re.search(r'\r?\n\r?\n(.+)', chunk, re.DOTALL)
            if body_m:
                body_text = body_m.group(1).strip()
                try:
                    ep["request_body"] = json.loads(body_text)
                except (json.JSONDecodeError, ValueError):
                    pass

            self._endpoints.append(ep)

    @property
    def tokens(self) -> list[str]:
        return self._tokens


def _parse_url(url: str) -> dict | None:
    m = _URL_RE.match(url)
    if not m:
        return None
    return {"host": m.group(1), "path": m.group(2) or "/"}
