"""APK extraction and decompilation."""
from __future__ import annotations

import re
import shutil
import subprocess
import zipfile
from pathlib import Path


class ApkUnpacker:
    """Unzip APK and optionally decompile DEX with jadx."""

    def __init__(self, apk_path: str, work_dir: Path, device: str | None = None) -> None:
        self.apk_path = Path(apk_path)
        self.work_dir = work_dir
        self.device = device

    def unpack(self) -> Path:
        """Unzip APK (and split APKs), decompile DEX. Returns output directory."""
        out = self.work_dir / "unpacked"
        out.mkdir(parents=True, exist_ok=True)

        # Unzip base APK
        with zipfile.ZipFile(self.apk_path, "r") as z:
            z.extractall(out / "raw")

        # Pull and unzip split APKs (app bundles put native libs in separate splits)
        self._unpack_splits(out)

        # Try jadx decompilation
        jadx_out = out / "jadx"
        if shutil.which("jadx"):
            subprocess.run(
                ["jadx", "-d", str(jadx_out), str(self.apk_path)],
                capture_output=True,
                timeout=300,
            )
        else:
            if shutil.which("apktool"):
                subprocess.run(
                    ["apktool", "d", "-f", "-o", str(out / "apktool"), str(self.apk_path)],
                    capture_output=True,
                    timeout=300,
                )

        return out

    def _unpack_splits(self, out: Path) -> None:
        """Pull split APKs from device and extract them."""
        if not self.device:
            return

        try:
            pkg = self.extract_package_name(str(self.apk_path), device=self.device)
            result = subprocess.run(
                ["adb", "-s", self.device, "shell", "pm", "path", pkg],
                capture_output=True, text=True, timeout=10,
            )
            split_dir = out / "splits"
            split_dir.mkdir(exist_ok=True)

            for line in result.stdout.splitlines():
                remote_path = line.strip().removeprefix("package:")
                if "split_" in remote_path:
                    local_name = Path(remote_path).name
                    local_path = split_dir / local_name
                    subprocess.run(
                        ["adb", "-s", self.device, "pull", remote_path, str(local_path)],
                        capture_output=True, timeout=60,
                    )
                    if local_path.exists() and zipfile.is_zipfile(local_path):
                        with zipfile.ZipFile(local_path, "r") as z:
                            z.extractall(out / "raw")
        except Exception:
            pass

    @staticmethod
    def extract_package_name(apk_path: str, device: str | None = None) -> str:
        """Extract package name from APK via aapt, jadx manifest, apktool, or device."""
        # Method 0: if device is provided and APK is installed, ask pm
        if device:
            try:
                # Get APK's cert fingerprint isn't practical; just try known installed packages
                result = subprocess.run(
                    ["adb", "-s", device, "shell", "pm", "list", "packages"],
                    capture_output=True, text=True, timeout=10,
                )
                # Try to match APK filename to an installed package
                apk_stem = Path(apk_path).stem.lower().replace("-", "").replace("_", "")
                for line in result.stdout.splitlines():
                    pkg = line.strip().removeprefix("package:")
                    pkg_clean = pkg.lower().replace(".", "")
                    if apk_stem in pkg_clean or pkg_clean in apk_stem:
                        return pkg
            except Exception:
                pass

        # Method 1: aapt
        if shutil.which("aapt"):
            result = subprocess.run(
                ["aapt", "dump", "badging", apk_path],
                capture_output=True, text=True, timeout=30,
            )
            m = re.search(r"package: name='([^']+)'", result.stdout)
            if m:
                return m.group(1)

        # Method 2: jadx already-decompiled manifest (check common session dirs)
        for parent in [Path(apk_path).parent, Path.home() / ".apkre"]:
            for manifest in parent.rglob("AndroidManifest.xml"):
                try:
                    content = manifest.read_text(errors="replace")
                    m = re.search(r'package="([^"]+)"', content)
                    if m:
                        return m.group(1)
                except OSError:
                    continue

        # Method 3: apktool
        if shutil.which("apktool"):
            import tempfile
            with tempfile.TemporaryDirectory() as tmp:
                subprocess.run(
                    ["apktool", "d", "-f", "-o", tmp, apk_path],
                    capture_output=True, timeout=120,
                )
                manifest = Path(tmp) / "AndroidManifest.xml"
                if manifest.exists():
                    content = manifest.read_text(errors="replace")
                    m = re.search(r'package="([^"]+)"', content)
                    if m:
                        return m.group(1)

        # Method 4: unzip and parse binary AXML
        with zipfile.ZipFile(apk_path, "r") as z:
            if "AndroidManifest.xml" in z.namelist():
                data = z.read("AndroidManifest.xml")
                text = data.decode("utf-8", errors="replace")
                # Try text manifest first (some APKs have plain XML)
                m = re.search(r'package="([^"]+)"', text)
                if m:
                    return m.group(1)
                # Binary AXML: look for reverse-DNS package patterns
                text_latin = data.decode("latin-1", errors="replace")
                # Filter out common noise like java.lang, android.content, etc.
                for m in re.finditer(r'([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){2,})', text_latin):
                    candidate = m.group(1)
                    if not candidate.startswith(("java.", "android.", "org.xml", "javax.")):
                        return candidate

        return "unknown.package"
