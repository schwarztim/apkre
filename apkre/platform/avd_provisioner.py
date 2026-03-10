"""Create and configure AVD instances from base image."""
from __future__ import annotations

import os
import random
import subprocess
from pathlib import Path

from apkre.platform.config import PlatformConfig
from apkre.platform.identity_randomizer import IdentityRandomizer
from apkre.platform.anti_detect import AntiDetect


class AvdProvisioner:
    SYSTEM_IMAGE = "system-images;android-31;google_apis;x86_64"

    def __init__(self, config: PlatformConfig) -> None:
        self.config = config

    def avd_name(self, instance_id: int) -> str:
        if not 1 <= instance_id <= self.config.max_avds:
            raise ValueError(f"instance_id must be 1-{self.config.max_avds}")
        return f"apkre_{instance_id:03d}"

    def create(self, instance_id: int, seed: int | None = None) -> Path:
        name = self.avd_name(instance_id)
        avd_home = self.config.avd_home(instance_id)
        avd_home.mkdir(parents=True, exist_ok=True)

        env = os.environ.copy()
        env.update({
            "ANDROID_SDK_ROOT": self.config.sdk_root,
            "ANDROID_AVD_HOME": str(self.config.avd_dir),
            "HOME": str(self.config.avd_dir),
        })

        subprocess.run(
            [
                self.config.avdmanager_binary, "create", "avd",
                "--name", name,
                "--package", self.SYSTEM_IMAGE,
                "--device", "Nexus 5X",
                "--force",
            ],
            capture_output=True, text=True, timeout=60,
            env=env,
            input="no\n",
        )

        identity = IdentityRandomizer.generate(instance_id, seed=seed)
        config_ini = self._generate_config_ini(instance_id)
        config_ini.update(AntiDetect.generate_avd_config_overrides())

        ini_path = avd_home / "config.ini"
        with open(ini_path, "w") as f:
            for key, value in sorted(config_ini.items()):
                f.write(f"{key}={value}\n")

        # Generate boot-time anti-detection script using resetprop
        anti_props = AntiDetect.generate_prop_overrides()
        identity_props = identity.to_props()
        all_props = {**anti_props, **identity_props}

        rng = random.Random(instance_id)
        battery_level = rng.randint(15, 95)
        adb_serial = f"emulator-{self.config.adb_port(instance_id)}"

        boot_script = AntiDetect.generate_boot_script(
            adb_binary=self.config.adb_binary,
            serial=adb_serial,
            props=all_props,
            battery_level=battery_level,
        )
        props_script = avd_home / "boot-props.sh"
        props_script.write_text(boot_script)
        props_script.chmod(0o755)

        return avd_home

    def _generate_config_ini(self, instance_id: int) -> dict[str, str]:
        return {
            "AvdId": self.avd_name(instance_id),
            "PlayStore.enabled": "false",
            "abi.type": "x86_64",
            "avd.ini.encoding": "UTF-8",
            "disk.dataPartition.size": "16G",
            "hw.accelerometer": "yes",
            "hw.battery": "yes",
            "hw.camera.back": "none",
            "hw.camera.front": "none",
            "hw.cpu.arch": "x86_64",
            "hw.cpu.ncore": "2",
            "hw.dPad": "no",
            "hw.gps": "yes",
            "hw.gpu.enabled": "yes",
            "hw.gpu.mode": "swiftshader_indirect",
            "hw.keyboard": "no",
            "hw.lcd.density": "420",
            "hw.lcd.height": "1920",
            "hw.lcd.width": "1080",
            "hw.mainKeys": "no",
            "hw.ramSize": str(self.config.avd_ram_mb),
            "hw.sdCard": "yes",
            "hw.sensors.orientation": "yes",
            "hw.sensors.proximity": "yes",
            "hw.trackBall": "no",
            "image.sysdir.1": f"{self.config.sdk_root}/system-images/android-31/google_apis/x86_64/",
            "tag.display": "Google APIs",
            "tag.id": "google_apis",
            "vm.heapSize": "256",
        }

    def list_instances(self) -> list[dict]:
        instances = []
        if not self.config.avd_dir.exists():
            return instances
        for avd_dir in sorted(self.config.avd_dir.iterdir()):
            if avd_dir.is_dir() and avd_dir.name.startswith("AVD_"):
                instance_id = int(avd_dir.name.split("_")[1])
                ini = avd_dir / "config.ini"
                instances.append({
                    "id": instance_id,
                    "name": self.avd_name(instance_id),
                    "path": str(avd_dir),
                    "configured": ini.exists(),
                })
        return instances
