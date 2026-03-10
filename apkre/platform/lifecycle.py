"""AVD lifecycle management: start, stop, health check, snapshots."""
from __future__ import annotations

import os
import subprocess
from enum import Enum

from apkre.platform.config import PlatformConfig


class AvdStatus(Enum):
    STOPPED = "stopped"
    BOOTING = "booting"
    RUNNING = "running"
    ERROR = "error"


class LifecycleManager:
    def __init__(self, config: PlatformConfig) -> None:
        self.config = config

    def _launch_args(self, instance_id: int) -> list[str]:
        name = f"apkre_{instance_id:03d}"
        port = self.config.adb_port(instance_id)
        return [
            self.config.emulator_binary,
            f"@{name}",
            "-no-window",
            "-no-audio",
            "-no-boot-anim",
            "-gpu", "swiftshader_indirect",
            "-port", str(port),
            "-no-snapshot-load",
            "-no-snapshot-save",
        ]

    def _env(self) -> dict[str, str]:
        env = os.environ.copy()
        env.update({
            "ANDROID_SDK_ROOT": self.config.sdk_root,
            "ANDROID_AVD_HOME": str(self.config.avd_dir),
            "ANDROID_EMULATOR_HOME": str(self.config.base_dir),
            "TMPDIR": "/data/tmp",
        })
        return env

    def start(self, instance_id: int) -> int:
        args = self._launch_args(instance_id)
        log_path = self.config.logs_dir / f"avd_{instance_id:03d}.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)

        with open(log_path, "a") as log:
            proc = subprocess.Popen(args, stdout=log, stderr=log, env=self._env())

        # Run boot-props script after boot completes
        props_script = self.config.avd_home(instance_id) / "boot-props.sh"
        if props_script.exists():
            # This will be called separately after boot_completed = 1
            pass

        return proc.pid

    def stop(self, instance_id: int) -> bool:
        port = self.config.adb_port(instance_id)
        serial = f"emulator-{port}"
        result = subprocess.run(
            [self.config.adb_binary, "-s", serial, "emu", "kill"],
            capture_output=True, text=True, timeout=30,
        )
        return result.returncode == 0

    def status(self, instance_id: int) -> AvdStatus:
        port = self.config.adb_port(instance_id)
        serial = f"emulator-{port}"
        result = subprocess.run(
            [self.config.adb_binary, "devices"],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            if serial in line:
                if "device" in line and "offline" not in line:
                    return AvdStatus.RUNNING
                if "offline" in line:
                    return AvdStatus.BOOTING
                return AvdStatus.ERROR
        return AvdStatus.STOPPED

    def status_all(self) -> dict[int, AvdStatus]:
        statuses = {}
        if not self.config.avd_dir.exists():
            return statuses
        for avd_dir in sorted(self.config.avd_dir.iterdir()):
            if avd_dir.is_dir() and avd_dir.name.startswith("AVD_"):
                instance_id = int(avd_dir.name.split("_")[1])
                statuses[instance_id] = self.status(instance_id)
        return statuses

    def wait_for_boot(self, instance_id: int, timeout: int = 120) -> bool:
        """Wait for AVD to finish booting, then apply props."""
        import time
        port = self.config.adb_port(instance_id)
        serial = f"emulator-{port}"
        deadline = time.time() + timeout

        while time.time() < deadline:
            result = subprocess.run(
                [self.config.adb_binary, "-s", serial, "shell", "getprop sys.boot_completed"],
                capture_output=True, text=True, timeout=10,
            )
            if result.stdout.strip() == "1":
                # Apply anti-detection props
                props_script = self.config.avd_home(instance_id) / "boot-props.sh"
                if props_script.exists():
                    subprocess.run(["bash", str(props_script)], timeout=30)
                return True
            time.sleep(2)
        return False

    def health_check(self, instance_id: int) -> dict:
        port = self.config.adb_port(instance_id)
        serial = f"emulator-{port}"
        checks = {"adb": False, "boot_complete": False, "network": False}

        result = subprocess.run(
            [self.config.adb_binary, "-s", serial, "shell", "echo ok"],
            capture_output=True, text=True, timeout=10,
        )
        checks["adb"] = result.returncode == 0 and "ok" in result.stdout
        if not checks["adb"]:
            return checks

        result = subprocess.run(
            [self.config.adb_binary, "-s", serial, "shell", "getprop sys.boot_completed"],
            capture_output=True, text=True, timeout=10,
        )
        checks["boot_complete"] = result.stdout.strip() == "1"

        result = subprocess.run(
            [self.config.adb_binary, "-s", serial, "shell", "ping -c1 -W2 8.8.8.8"],
            capture_output=True, text=True, timeout=10,
        )
        checks["network"] = result.returncode == 0
        return checks

    def snapshot_save(self, instance_id: int, name: str = "default") -> bool:
        port = self.config.adb_port(instance_id)
        serial = f"emulator-{port}"
        result = subprocess.run(
            [self.config.adb_binary, "-s", serial, "emu", "avd", "snapshot", "save", name],
            capture_output=True, text=True, timeout=60,
        )
        return result.returncode == 0

    def generate_systemd_unit(self, instance_id: int) -> str:
        name = f"apkre_{instance_id:03d}"
        args = self._launch_args(instance_id)
        exec_start = " ".join(args)
        return f"""[Unit]
Description=apkre AVD Instance {name}
After=network.target

[Service]
Type=simple
User=tim
Environment=ANDROID_SDK_ROOT={self.config.sdk_root}
Environment=ANDROID_AVD_HOME={self.config.avd_dir}
Environment=ANDROID_EMULATOR_HOME={self.config.base_dir}
Environment=TMPDIR=/data/tmp
ExecStart={exec_start}
ExecStartPost=/bin/bash {self.config.avd_home(instance_id)}/boot-props.sh
Restart=on-failure
RestartSec=10
TimeoutStopSec=30
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
"""
