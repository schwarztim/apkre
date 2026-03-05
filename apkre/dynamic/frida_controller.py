"""Frida spawn + inject controller — Frida 17.x compatible."""
from __future__ import annotations

import json
import re
import subprocess
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
_HOST_HEADER_RE = re.compile(
    r'^Host:\s*(\S+)', re.MULTILINE | re.IGNORECASE,
)
_URL_RE = re.compile(r'https?://([^/\s?#]+)(/[^\s?#]*)?')


class FridaController:
    """Spawn or attach to an Android app with Frida, inject SSL hooks, collect captured requests."""

    def __init__(self, device_serial: str, package: str, console: Console) -> None:
        self.device_serial = device_serial
        self.package = package
        self.console = console
        self._endpoints: list[dict] = []
        self._tokens: list[str] = []
        self._seen_keys: set[str] = set()

    def start_background(self, mode: str = "attach") -> None:
        """Start Frida capture in a background daemon thread."""
        self._bg_stop = Event()
        self._bg_session = None

        if not FRIDA_AVAILABLE:
            self.console.print("[red]frida not installed. Run: pip install frida frida-tools[/red]")
            return

        def _run():
            try:
                try:
                    device = frida.get_device(self.device_serial)
                except frida.InvalidArgumentError:
                    device = frida.get_usb_device()

                agent_js = _AGENT_JS.read_text()

                def on_message(message: dict, data) -> None:
                    if message.get("type") != "send":
                        return
                    payload = message.get("payload", {})
                    mtype = payload.get("type", "")
                    if mtype in ("ssl_write", "ssl_read"):
                        self._parse_http_chunk(payload.get("data", ""), mtype)
                    elif mtype == "okhttp":
                        url = payload.get("url", "")
                        parsed = _parse_url(url)
                        if parsed:
                            key = f"{payload.get('method','GET')}:{parsed['host']}:{parsed['path']}"
                            if key not in self._seen_keys:
                                self._seen_keys.add(key)
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

                if mode == "attach":
                    session, pid = self._attach(device, agent_js, on_message)
                else:
                    session, pid = self._spawn(device, agent_js, on_message)

                self._bg_session = session
                self._bg_stop.wait()

                try:
                    session.detach()
                except Exception:
                    pass
            except Exception as e:
                self.console.print(f"  [red]Frida background error: {e}[/red]")

        from threading import Thread
        t = Thread(target=_run, daemon=True)
        t.start()
        self._bg_thread = t

    def stop_background(self) -> list[dict]:
        """Stop background Frida capture and return collected endpoints."""
        if hasattr(self, '_bg_stop'):
            self._bg_stop.set()
        if hasattr(self, '_bg_thread'):
            self._bg_thread.join(timeout=10)
        return self._endpoints

    def capture(self, timeout: int = 300, mode: str = "spawn") -> list[dict]:
        """Capture traffic via Frida.

        mode:
            "spawn"  — spawn the app fresh (kills existing instance, full control)
            "attach" — attach to running app (preserves state, no routing breakage)
        """
        if not FRIDA_AVAILABLE:
            self.console.print("[red]frida not installed. Run: pip install frida frida-tools[/red]")
            return []

        try:
            device = frida.get_device(self.device_serial)
        except frida.InvalidArgumentError:
            device = frida.get_usb_device()

        agent_js = _AGENT_JS.read_text()

        def on_message(message: dict, data: Any) -> None:
            if message.get("type") != "send":
                return
            payload = message.get("payload", {})
            mtype = payload.get("type", "")

            if mtype == "agent_ready":
                self.console.print("  [green]✓[/green] Frida agent ready")

            elif mtype == "hook_ok":
                self.console.print(f"  [green]✓[/green] Hooked: {payload.get('label')}")

            elif mtype == "hook_info":
                self.console.print(f"  [dim]{payload.get('label')}: {payload.get('msg')}[/dim]")

            elif mtype == "hook_error":
                self.console.print(f"  [red]Hook error[/red] {payload.get('label')}: {payload.get('error')}")

            elif mtype in ("ssl_write", "ssl_read"):
                chunk = payload.get("data", "")
                self._parse_http_chunk(chunk, mtype)

            elif mtype == "okhttp":
                url = payload.get("url", "")
                parsed = _parse_url(url)
                if parsed:
                    key = f"{payload.get('method','GET')}:{parsed['host']}:{parsed['path']}"
                    if key not in self._seen_keys:
                        self._seen_keys.add(key)
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

        if mode == "attach":
            session, pid = self._attach(device, agent_js, on_message)
        else:
            session, pid = self._spawn(device, agent_js, on_message)

        self.console.print(f"  App {mode}ed (pid={pid}), capturing for {timeout}s...")
        deadline = time.time() + timeout
        try:
            while time.time() < deadline:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            try:
                session.detach()
            except Exception:
                pass

        return self._endpoints

    def _spawn(self, device, agent_js: str, on_message) -> tuple:
        """Spawn the app fresh and inject agent."""
        pid = device.spawn([self.package])
        session = device.attach(pid)
        script = session.create_script(agent_js)
        script.on("message", on_message)
        script.load()
        device.resume(pid)
        return session, pid

    def _attach(self, device, agent_js: str, on_message) -> tuple:
        """Attach to a running app instance (no restart, preserves routing)."""
        # Find the running PID
        pid = self._find_pid()
        if pid is None:
            self.console.print("  [yellow]![/yellow] App not running, falling back to spawn mode")
            return self._spawn(device, agent_js, on_message)

        session = device.attach(pid)
        script = session.create_script(agent_js)
        script.on("message", on_message)
        script.load()
        return session, pid

    def _find_pid(self) -> int | None:
        """Find PID of running package via adb."""
        try:
            result = subprocess.run(
                ["adb", "-s", self.device_serial, "shell", "pidof", self.package],
                capture_output=True, text=True, timeout=5,
            )
            pid_str = result.stdout.strip()
            if pid_str:
                return int(pid_str.split()[0])
        except Exception:
            pass
        return None

    def _parse_http_chunk(self, chunk: str, direction: str) -> None:
        """Parse raw HTTP text captured from SSL buffer."""
        # Extract Host header for path-only requests
        host_m = _HOST_HEADER_RE.search(chunk)
        default_host = host_m.group(1) if host_m else ""

        for m in _HTTP_REQUEST_RE.finditer(chunk):
            method = m.group(1)
            url_or_path = m.group(2)

            if url_or_path.startswith("http"):
                parsed = _parse_url(url_or_path)
            else:
                parsed = {"path": url_or_path, "host": default_host}

            if not parsed:
                continue

            key = f"{method}:{parsed['host']}:{parsed['path']}"
            if key in self._seen_keys:
                continue
            self._seen_keys.add(key)

            auth = bool(_AUTH_HEADER_RE.search(chunk))
            ep = {
                **parsed,
                "method": method,
                "source": "frida-ssl",
                "auth": auth,
            }

            # Extract auth token
            am = _AUTH_HEADER_RE.search(chunk)
            if am:
                token_val = am.group(1).strip()
                if token_val not in self._tokens:
                    self._tokens.append(token_val)

            # Extract request body (after blank line)
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
