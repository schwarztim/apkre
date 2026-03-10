"""Platform configuration for emulator farm."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class PlatformConfig:
    """Configuration for the apkre emulator farm."""

    base_dir: Path = field(default_factory=lambda: Path("/data/apkre"))
    max_avds: int = 100
    avd_ram_mb: int = 2048
    vnc_base_port: int = 5900
    adb_base_port: int = 5554
    emulator_binary: str = "/data/android-sdk/emulator/emulator"
    adb_binary: str = "/data/android-sdk/platform-tools/adb"
    avdmanager_binary: str = "/data/android-sdk/cmdline-tools/latest/bin/avdmanager"
    sdk_root: str = "/data/android-sdk"

    @property
    def avd_dir(self) -> Path:
        return self.base_dir / "avds"

    @property
    def base_image_dir(self) -> Path:
        return self.base_dir / "base-image"

    @property
    def snapshots_dir(self) -> Path:
        return self.base_dir / "snapshots"

    @property
    def config_dir(self) -> Path:
        return self.base_dir / "config"

    @property
    def logs_dir(self) -> Path:
        return self.base_dir / "logs"

    @property
    def results_dir(self) -> Path:
        return self.base_dir / "results"

    def ensure_dirs(self) -> None:
        for d in [self.avd_dir, self.base_image_dir, self.snapshots_dir,
                  self.config_dir, self.logs_dir, self.results_dir]:
            d.mkdir(parents=True, exist_ok=True)

    def avd_home(self, instance_id: int) -> Path:
        return self.avd_dir / f"AVD_{instance_id:03d}"

    def vnc_port(self, instance_id: int) -> int:
        return self.vnc_base_port + instance_id

    def adb_port(self, instance_id: int) -> int:
        return self.adb_base_port + (instance_id * 2)
