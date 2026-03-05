"""Flutter/Dart-specific static extraction: libapp.so string scan + reFlutter."""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

_URL_RE = re.compile(r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+')
_PATH_RE = re.compile(r'(/(?:api|v\d+|iot-service|user|device|auth)[/a-zA-Z0-9_\-{}]+)')


class DartScanner:
    """Extract endpoints from Flutter AOT snapshots (libapp.so / libflutter.so)."""

    def __init__(self, unpacked_dir: Path) -> None:
        self.root = unpacked_dir

    def scan(self) -> list[dict]:
        endpoints: list[dict] = []
        seen: set[str] = set()

        # Locate libapp.so (Dart AOT snapshot)
        for libapp in self.root.rglob("libapp.so"):
            endpoints.extend(self._scan_binary(libapp, seen))

        # reFlutter: if available, use it for deeper extraction
        if shutil.which("reflutter"):
            endpoints.extend(self._reflutter_scan(seen))

        return endpoints

    def _scan_binary(self, lib_path: Path, seen: set[str]) -> list[dict]:
        """Run strings on binary and extract URL/path patterns."""
        result: list[dict] = []

        if shutil.which("strings"):
            proc = subprocess.run(
                ["strings", "-n", "8", str(lib_path)],
                capture_output=True, text=True, timeout=60,
            )
            text = proc.stdout
        else:
            # Fallback: read and decode printable ASCII
            data = lib_path.read_bytes()
            text = _extract_strings(data)

        for m in _URL_RE.finditer(text):
            url = m.group(0).rstrip(".,;\"')")
            parsed = _parse_url(url)
            if parsed and parsed["path"] not in seen:
                seen.add(parsed["path"])
                result.append({**parsed, "source": "dart-binary", "method": "GET", "auth": False})

        for line in text.splitlines():
            line = line.strip()
            for m in _PATH_RE.finditer(line):
                path = m.group(1)
                if path not in seen and len(path) > 4:
                    seen.add(path)
                    result.append({
                        "path": path, "host": "", "source": "dart-binary",
                        "method": "?", "auth": False,
                    })

        return result

    def _reflutter_scan(self, seen: set[str]) -> list[dict]:
        """Use reFlutter to dump routes from Dart snapshot if available."""
        # reFlutter outputs a routes file; this is a best-effort integration
        apk_candidates = list(self.root.parent.parent.glob("*.apk"))
        if not apk_candidates:
            return []

        apk = apk_candidates[0]
        out_dir = self.root / "reflutter"
        out_dir.mkdir(exist_ok=True)

        subprocess.run(
            ["reflutter", str(apk), "--recompile"],
            capture_output=True, timeout=120, cwd=str(out_dir),
        )

        results: list[dict] = []
        for routes_file in out_dir.rglob("routes.txt"):
            for line in routes_file.read_text(errors="replace").splitlines():
                line = line.strip()
                if line.startswith("/") and line not in seen:
                    seen.add(line)
                    results.append({
                        "path": line, "host": "", "source": "reflutter",
                        "method": "?", "auth": False,
                    })
        return results


def _extract_strings(data: bytes, min_len: int = 8) -> str:
    """Extract printable ASCII strings from binary data."""
    result = []
    current: list[int] = []
    for b in data:
        if 0x20 <= b < 0x7F:
            current.append(b)
        else:
            if len(current) >= min_len:
                result.append(bytes(current).decode("ascii"))
            current = []
    return "\n".join(result)


def _parse_url(url: str) -> dict | None:
    m = re.match(r'https?://([^/?\s#]+)(/[^?\s#]*)?', url)
    if not m:
        return None
    return {"host": m.group(1), "path": m.group(2) or "/"}
