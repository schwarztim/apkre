"""Auth token extraction: heap dump, SharedPrefs, memory scan."""
from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

from rich.console import Console

_JWT_RE  = re.compile(r'eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}(?:\.[A-Za-z0-9_\-]+)?')
_BEARER_RE = re.compile(r'Bearer\s+([A-Za-z0-9_\-\.]{20,})', re.IGNORECASE)


class TokenExtractor:
    """Multi-method auth token extractor for Android apps."""

    def __init__(self, device: str, package: str, console: Console) -> None:
        self.device = device
        self.package = package
        self.console = console

    def extract(self) -> list[str]:
        """Try all extraction methods in priority order, return unique tokens."""
        tokens: list[str] = []

        # Method 1: heap dump
        tokens.extend(self._heap_dump_scan())

        # Method 2: SharedPreferences files
        tokens.extend(self._shared_prefs_scan())

        # Method 3: Frida SharedPrefs (via separate mini-script)
        tokens.extend(self._frida_prefs_dump())

        # Deduplicate
        seen: set[str] = set()
        unique: list[str] = []
        for t in tokens:
            if t not in seen:
                seen.add(t)
                unique.append(t)
        return unique

    def _heap_dump_scan(self) -> list[str]:
        """Dump app heap to /tmp, pull it, scan for JWT tokens."""
        try:
            pid_out = subprocess.run(
                ["adb", "-s", self.device, "shell", "pidof", self.package],
                capture_output=True, text=True, timeout=10,
            ).stdout.strip()

            if not pid_out:
                return []

            remote_hprof = f"/data/local/tmp/{self.package}.hprof"
            subprocess.run(
                ["adb", "-s", self.device, "shell", "am", "dumpheap", pid_out, remote_hprof],
                capture_output=True, timeout=30,
            )

            with tempfile.NamedTemporaryFile(suffix=".hprof", delete=False) as f:
                local_hprof = f.name

            subprocess.run(
                ["adb", "-s", self.device, "pull", remote_hprof, local_hprof],
                capture_output=True, timeout=30,
            )

            data = Path(local_hprof).read_bytes()
            text = data.decode("latin-1", errors="replace")

            tokens: list[str] = []
            for m in _JWT_RE.finditer(text):
                tokens.append(m.group(0))
            for m in _BEARER_RE.finditer(text):
                tokens.append(m.group(1))

            return tokens

        except Exception as e:
            self.console.print(f"  [dim]heap dump failed: {e}[/dim]")
            return []

    def _shared_prefs_scan(self) -> list[str]:
        """Read SharedPreferences XML files from app data dir.

        Tries run-as first (debuggable apps), falls back to direct cat (root).
        """
        prefs_dir = f"/data/data/{self.package}/shared_prefs/"
        tokens: list[str] = []

        for method in ["run-as", "root"]:
            try:
                if method == "run-as":
                    ls_cmd = ["adb", "-s", self.device, "shell", "run-as", self.package, "ls", prefs_dir]
                    cat_prefix = ["adb", "-s", self.device, "shell", "run-as", self.package, "cat"]
                else:
                    ls_cmd = ["adb", "-s", self.device, "shell", "ls", prefs_dir]
                    cat_prefix = ["adb", "-s", self.device, "shell", "cat"]

                result = subprocess.run(ls_cmd, capture_output=True, text=True, timeout=10)
                if result.returncode != 0:
                    continue

                prefs_files = [f.strip() for f in result.stdout.splitlines() if f.strip().endswith(".xml")]

                for fname in prefs_files:
                    cat = subprocess.run(
                        [*cat_prefix, prefs_dir + fname],
                        capture_output=True, text=True, timeout=10,
                    )
                    text = cat.stdout
                    for m in _JWT_RE.finditer(text):
                        tokens.append(m.group(0))
                    for m in _BEARER_RE.finditer(text):
                        tokens.append(m.group(1))

                if tokens:
                    return tokens
            except Exception:
                continue

        return tokens

    def _frida_prefs_dump(self) -> list[str]:
        """Use a minimal Frida script to dump SharedPreferences via Java API."""
        try:
            import frida  # type: ignore
        except ImportError:
            return []

        mini_script = """
Java.perform(function() {
    try {
        var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
        var File = Java.use('java.io.File');
        var prefsDir = new File(ctx.getApplicationInfo().dataDir.value + '/shared_prefs');
        var files = prefsDir.listFiles();
        if (!files) return;
        for (var f = 0; f < files.length; f++) {
            var name = files[f].getName().replace('.xml', '');
            try {
                var pref = ctx.getSharedPreferences(name, 0);
                var all = pref.getAll();
                var keys = all.keySet().toArray();
                for (var i = 0; i < keys.length; i++) {
                    var val = all.get(keys[i]);
                    if (val !== null) {
                        var s = val.toString();
                        if (s.length > 20) {
                            send({type: 'pref', key: name + '/' + keys[i].toString(), value: s});
                        }
                    }
                }
            } catch(e2) {}
        }
    } catch(e) { send({type: 'pref_error', msg: e.message}); }
});
"""
        tokens: list[str] = []
        try:
            device = frida.get_device(self.device)
            pid_str = subprocess.run(
                ["adb", "-s", self.device, "shell", "pidof", self.package],
                capture_output=True, text=True, timeout=5,
            ).stdout.strip()
            if not pid_str:
                return []
            # pidof may return multiple PIDs; take the first one
            pid = int(pid_str.split()[0])
            session = device.attach(pid)
            script = session.create_script(mini_script)
            collected: list[str] = []

            def on_msg(msg, _data):
                if msg.get("type") == "send":
                    p = msg.get("payload", {})
                    if p.get("type") == "pref":
                        val = p.get("value", "")
                        for m in _JWT_RE.finditer(val):
                            collected.append(m.group(0))
                        for m in _BEARER_RE.finditer(val):
                            collected.append(m.group(1))

            script.on("message", on_msg)
            script.load()
            import time; time.sleep(2)
            script.unload()
            session.detach()
            return collected

        except Exception as e:
            self.console.print(f"  [dim]frida prefs dump failed: {e}[/dim]")
            return []
