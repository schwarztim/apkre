"""Check prerequisites: adb, frida-server, mitmproxy CA cert."""
from __future__ import annotations

import shutil
import subprocess

from rich.console import Console
from rich.table import Table


class PrereqChecker:
    """Verify all required tools and device state before analysis."""

    def __init__(self, console: Console) -> None:
        self.console = console

    def check(self, device: str | None = None, fix: bool = False) -> bool:
        table = Table(title="Prerequisites", show_header=True)
        table.add_column("Check", style="white")
        table.add_column("Status", style="bold")
        table.add_column("Notes", style="dim")

        all_ok = True

        checks = [
            ("adb",            self._check_adb),
            ("jadx",           self._check_jadx),
            ("frida (Python)", self._check_frida_python),
            ("mitmproxy",      self._check_mitmproxy),
            ("strings",        self._check_strings),
        ]

        if device:
            checks.append(("adb device",       lambda: self._check_device(device)))
            checks.append(("frida-server",     lambda: self._check_frida_server(device)))
            checks.append(("device clock",     lambda: self._check_clock(device)))

        for name, fn in checks:
            ok, note = fn()
            status = "[green]✓ OK[/green]" if ok else "[red]✗ MISSING[/red]"
            table.add_row(name, status, note)
            if not ok:
                all_ok = False

        self.console.print(table)

        if not all_ok and fix:
            self._attempt_fixes(device)

        return all_ok

    def _check_adb(self) -> tuple[bool, str]:
        ok = bool(shutil.which("adb"))
        return ok, "" if ok else "Install Android SDK platform-tools"

    def _check_jadx(self) -> tuple[bool, str]:
        ok = bool(shutil.which("jadx"))
        return ok, "" if ok else "brew install jadx (or https://github.com/skylot/jadx)"

    def _check_frida_python(self) -> tuple[bool, str]:
        try:
            import frida
            return True, f"v{frida.__version__}"
        except ImportError:
            return False, "pip install frida frida-tools"

    def _check_mitmproxy(self) -> tuple[bool, str]:
        ok = bool(shutil.which("mitmdump"))
        return ok, "" if ok else "pip install mitmproxy"

    def _check_strings(self) -> tuple[bool, str]:
        ok = bool(shutil.which("strings"))
        return ok, "" if ok else "Install binutils (brew install binutils)"

    def _check_device(self, device: str) -> tuple[bool, str]:
        result = subprocess.run(
            ["adb", "devices"], capture_output=True, text=True, timeout=10,
        )
        ok = device in result.stdout
        return ok, "" if ok else f"Device {device} not found in adb devices"

    def _check_frida_server(self, device: str) -> tuple[bool, str]:
        result = subprocess.run(
            ["adb", "-s", device, "shell", "pgrep", "-x", "frida-server"],
            capture_output=True, text=True, timeout=10,
        )
        ok = bool(result.stdout.strip())
        return ok, "" if ok else "Push & start frida-server on device (see docs)"

    def _check_clock(self, device: str) -> tuple[bool, str]:
        """Check device clock is within 5 minutes of host."""
        import time
        result = subprocess.run(
            ["adb", "-s", device, "shell", "date", "+%s"],
            capture_output=True, text=True, timeout=10,
        )
        try:
            device_ts = int(result.stdout.strip())
            diff = abs(device_ts - int(time.time()))
            ok = diff < 300
            return ok, "" if ok else f"Clock off by {diff}s — run apkre device-setup"
        except (ValueError, TypeError):
            return False, "Could not read device clock"

    def _attempt_fixes(self, device: str | None) -> None:
        self.console.print("\n[yellow]Attempting automatic fixes...[/yellow]")
        if device:
            from apkre.device.setup import DeviceSetup
            setup = DeviceSetup(device, self.console)
            setup.sync_clock()
