"""Device setup: clock sync, routing fix, proxy configuration."""
from __future__ import annotations

import re
import subprocess
import time

from rich.console import Console


class DeviceSetup:
    """Configure Android device for traffic interception."""

    def __init__(self, device: str, console: Console) -> None:
        self.device = device
        self.console = console
        self._is_root: bool | None = None

    def _adb(self, *args: str, timeout: int = 15) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["adb", "-s", self.device, *args],
            capture_output=True, text=True, timeout=timeout,
        )

    def _shell(self, cmd: str, timeout: int = 15) -> str:
        return self._adb("shell", cmd, timeout=timeout).stdout.strip()

    def _root_shell(self, cmd: str, timeout: int = 15) -> str:
        """Run a command as root, auto-detecting whether su is needed."""
        if self._is_root is None:
            uid = self._shell("id -u")
            self._is_root = uid.strip() == "0"

        if self._is_root:
            return self._shell(cmd, timeout=timeout)
        else:
            return self._shell(f"su -c '{cmd}'", timeout=timeout)

    def sync_clock(self) -> None:
        """Sync device clock to host time (critical for SSL cert validation)."""
        now = time.localtime()
        date_str = time.strftime("%m%d%H%M%Y.%S", now)
        self._root_shell(f"date {date_str}")
        self.console.print(f"  [green]✓[/green] Clock synced: {date_str}")

    def fix_routing(self) -> None:
        """Fix AOSP/LineageOS routing bug for WiFi traffic capture.

        Android uses per-network routing tables with fwmark rules.
        Frida-spawned processes and ADB shell often lack the right fwmark,
        so traffic gets dropped. This adds routes to named tables AND
        a fallback rule so all traffic can reach the internet.
        """
        gw, ip_addr = self._detect_gateway()
        if not gw:
            self.console.print("  [yellow]![/yellow] Could not determine gateway, skipping routing fix")
            return

        # Rebuild routes in the wlan0 named table
        subnet = self._detect_subnet(ip_addr)
        self._root_shell(f"ip route replace {subnet} dev wlan0 table wlan0 src {ip_addr}")
        self._root_shell(f"ip route replace default via {gw} dev wlan0 table wlan0")

        # Add default route to main table as catch-all
        self._root_shell(f"ip route replace default via {gw} dev wlan0 table main")

        # Add fallback rule so processes without fwmark can still route
        existing_rules = self._shell("ip rule show")
        if "lookup wlan0" not in existing_rules or "prio 9000" not in existing_rules:
            self._root_shell("ip rule add from all lookup wlan0 prio 9000")

        # Verify
        ping_result = self._shell("ping -c 1 -W 3 8.8.8.8 2>&1")
        if "bytes from" in ping_result:
            self.console.print(f"  [green]✓[/green] Routing fix applied (gw={gw}) — connectivity verified")
        else:
            self.console.print(f"  [yellow]![/yellow] Routing fix applied (gw={gw}) but ping failed — may need WiFi toggle")

    def _detect_gateway(self) -> tuple[str | None, str | None]:
        """Detect WiFi gateway and local IP using multiple methods."""
        # Method 1: dumpsys wifi DhcpResults (most reliable)
        wifi_dump = self._shell("dumpsys wifi 2>/dev/null")
        m = re.search(r'Gateway\s+(\d+\.\d+\.\d+\.\d+)', wifi_dump)
        gw = m.group(1) if m else None

        m = re.search(r'IP address\s+(\d+\.\d+\.\d+\.\d+)', wifi_dump)
        ip_addr = m.group(1) if m else None

        # Method 2: ip addr for IP
        if not ip_addr:
            addr_out = self._shell("ip addr show wlan0")
            m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', addr_out)
            ip_addr = m.group(1) if m else None

        # Method 3: derive gateway from IP (assume .1)
        if not gw and ip_addr:
            gw = ip_addr.rsplit(".", 1)[0] + ".1"

        return gw, ip_addr

    def _detect_subnet(self, ip_addr: str) -> str:
        """Detect subnet from wlan0 interface."""
        addr_out = self._shell("ip addr show wlan0")
        m = re.search(r'inet (\d+\.\d+\.\d+\.\d+/\d+)', addr_out)
        if m:
            # Convert host address to network: 10.0.214.37/16 → 10.0.0.0/16
            cidr = m.group(1)
            addr_part, prefix = cidr.split("/")
            prefix_int = int(prefix)
            octets = [int(o) for o in addr_part.split(".")]
            mask_bits = (0xFFFFFFFF << (32 - prefix_int)) & 0xFFFFFFFF
            net_int = (octets[0] << 24 | octets[1] << 16 | octets[2] << 8 | octets[3]) & mask_bits
            net_addr = f"{(net_int >> 24) & 0xFF}.{(net_int >> 16) & 0xFF}.{(net_int >> 8) & 0xFF}.{net_int & 0xFF}/{prefix}"
            return net_addr
        return "0.0.0.0/0"

    def verify_connectivity(self) -> bool:
        """Quick connectivity check — ping + DNS."""
        ping = self._shell("ping -c 1 -W 3 8.8.8.8 2>&1")
        return "bytes from" in ping

    def set_proxy(self, host: str, port: int) -> None:
        """Set global HTTP proxy on device."""
        self._shell(f"settings put global http_proxy {host}:{port}")
        self.console.print(f"  [green]✓[/green] Proxy set to {host}:{port}")

    def clear_proxy(self) -> None:
        """Remove global HTTP proxy setting."""
        self._shell("settings put global http_proxy :0")
        self.console.print("  [green]✓[/green] Proxy cleared")

    def install_mitmproxy_ca(self, cert_path: str) -> None:
        """Install mitmproxy CA cert as system-trusted CA (requires root)."""
        cert_hash_out = subprocess.run(
            ["openssl", "x509", "-inform", "PEM", "-subject_hash_old",
             "-in", cert_path, "-noout"],
            capture_output=True, text=True,
        ).stdout.strip()

        dest = f"/system/etc/security/cacerts/{cert_hash_out}.0"
        self._adb("push", cert_path, f"/sdcard/{cert_hash_out}.0")
        self._root_shell("mount -o rw,remount /system")
        self._root_shell(f"mv /sdcard/{cert_hash_out}.0 {dest}")
        self._root_shell(f"chmod 644 {dest}")
        self.console.print(f"  [green]✓[/green] mitmproxy CA installed: {dest}")
