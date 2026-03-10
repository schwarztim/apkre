"""Emulator anti-detection hardening."""
from __future__ import annotations

from pathlib import Path


# Android 12+ stores product props per-partition. All must be spoofed.
_PARTITIONS = ["", "bootimage", "odm", "product", "system", "system_ext", "vendor", "vendor_dlkm"]


class AntiDetect:
    """Hides emulator artifacts so apps cannot detect AVD environment."""

    # Props to delete entirely (emulator-specific)
    PROPS_TO_DELETE = [
        "ro.kernel.qemu.gles",
        "ro.emulator",
        "ro.hardware.audio.primary",
        "qemu.hw.mainkeys",
        "qemu.sf.lcd_density",
        "ro.boot.qemu.avd_name",
        "ro.boot.qemu.gltransport.name",
    ]

    # Device files that reveal emulator
    EMULATOR_ARTIFACTS = [
        "/dev/qemu_pipe",
        "/dev/goldfish_pipe",
        "/dev/goldfish_address_space",
        "/dev/goldfish_sync",
    ]

    @classmethod
    def generate_prop_overrides(
        cls,
        device_model: str = "Nexus 5X",
        device_brand: str = "LGE",
        device_hardware: str = "bullhead",
        device_board: str = "bullhead",
        device_manufacturer: str = "LGE",
        device_name: str = "bullhead",
        build_fingerprint: str = "google/bullhead/bullhead:8.1.0/OPM7.181205.001/5080180:user/release-keys",
    ) -> dict[str, str]:
        props: dict[str, str] = {}

        # Product props across all partitions
        product_values = {
            "brand": device_brand,
            "device": device_hardware,
            "manufacturer": device_manufacturer,
            "model": device_model,
            "name": device_name,
        }
        for partition in _PARTITIONS:
            prefix = f"ro.product.{partition}." if partition else "ro.product."
            for key, value in product_values.items():
                props[f"{prefix}{key}"] = value

        # Build props across all partitions
        for partition in _PARTITIONS:
            prefix = f"ro.{partition}.build." if partition else "ro.build."
            props[f"{prefix}tags"] = "release-keys"
            props[f"{prefix}type"] = "user"

        # Hardware props
        props.update({
            "ro.hardware": device_hardware,
            "ro.boot.hardware": device_hardware,
            "ro.board.platform": "msm8992",
            "ro.hardware.chipname": "msm8992",
            "ro.soc.manufacturer": "Qualcomm",
            "ro.soc.model": "MSM8992",
            "ro.build.display.id": "OPM7.181205.001",
            "ro.build.fingerprint": build_fingerprint,
            "ro.kernel.qemu": "0",
            "ro.boot.qemu": "0",
            # Telephony
            "gsm.version.baseband": "M8994F-2.6.36.2.20",
            "gsm.operator.alpha": "T-Mobile",
            "gsm.operator.numeric": "310260",
            "gsm.sim.operator.alpha": "T-Mobile",
            "gsm.sim.operator.numeric": "310260",
            "ro.setupwizard.mode": "DISABLED",
        })

        return props

    @classmethod
    def generate_boot_script(
        cls,
        adb_binary: str,
        serial: str,
        props: dict[str, str],
        battery_level: int = 73,
    ) -> str:
        """Generate a boot-time anti-detection script using resetprop.

        Uses delete-then-set pattern because Android 12 caches ro.product.*
        props from partition-specific build.prop files. A simple resetprop set
        may not override the cached value; deleting first forces a clean set.
        """
        lines = [
            "#!/bin/bash",
            "# Auto-generated anti-detection hardening script",
            "# Uses Magisk resetprop with delete-then-set for ro.* props",
            "",
            f'ADB="{adb_binary} -s {serial}"',
            "",
            "# Wait for boot",
            "for i in $(seq 1 60); do",
            '  $ADB shell getprop sys.boot_completed 2>/dev/null | grep -q 1 && break',
            "  sleep 2",
            "done",
            "",
            "# Enable root via adb",
            "$ADB root >/dev/null 2>&1",
            "sleep 1",
            "",
            "# === Property Spoofing (delete-then-set via resetprop) ===",
        ]
        for key, value in sorted(props.items()):
            if value:
                # Escape single quotes in value
                escaped = value.replace("'", "'\\''")
                lines.append(
                    f"$ADB shell \"resetprop --delete {key} 2>/dev/null; "
                    f"resetprop {key} '{escaped}'\""
                )
            else:
                lines.append(f"$ADB shell resetprop --delete {key} 2>/dev/null")

        # Delete emulator-only props
        lines.append("")
        lines.append("# === Delete Emulator-Only Props ===")
        for prop in cls.PROPS_TO_DELETE:
            lines.append(f"$ADB shell resetprop --delete {prop} 2>/dev/null")

        # Hide device files
        lines.extend([
            "",
            "# === Hide Emulator Device Files ===",
        ])
        for artifact in cls.EMULATOR_ARTIFACTS:
            lines.append(
                f'$ADB shell "[ -e {artifact} ] && mv {artifact} {artifact}.hidden" 2>/dev/null'
            )

        # Battery simulation
        lines.extend([
            "",
            "# === Battery Simulation ===",
            f"$ADB emu power capacity {battery_level}",
            "$ADB emu power ac off",
            "$ADB emu power status discharging",
            "$ADB emu power present true",
            "$ADB emu power health good",
            "",
            "# === Sensor Noise ===",
            "$ADB emu sensor set acceleration 0.2:9.77:-0.5",
            "$ADB emu sensor set magnetic-field 5.1:-20.3:43.8",
            "$ADB emu sensor set gyroscope 0.001:-0.002:0.001",
            "$ADB emu sensor set temperature 25.0",
            "$ADB emu sensor set proximity 5.0",
            "$ADB emu sensor set light 250.0",
            "$ADB emu sensor set pressure 1013.25",
            "$ADB emu sensor set humidity 45.0",
        ])
        return "\n".join(lines) + "\n"

    @classmethod
    def generate_avd_config_overrides(cls) -> dict[str, str]:
        return {
            "hw.sensors.proximity": "yes",
            "hw.sensors.magnetic_field": "yes",
            "hw.sensors.orientation": "yes",
            "hw.sensors.temperature": "yes",
            "hw.sensors.light": "yes",
            "hw.sensors.pressure": "yes",
            "hw.sensors.humidity": "yes",
            "hw.accelerometer": "yes",
            "hw.gyroscope": "yes",
            "hw.gps": "yes",
            "hw.battery": "yes",
            "hw.dPad": "no",
            "hw.keyboard": "no",
            "hw.trackBall": "no",
            "hw.arc": "false",
        }

    @classmethod
    def build_magisk_module(cls, output_dir: Path) -> Path:
        """Build a Magisk module that hides vendor-level emulator artifacts.

        This module:
        1. Overlays /vendor/etc/init/hw/init.ranchu.rc with an empty file
        2. Runs a post-fs-data script to hide /dev emulator artifacts on every boot
        3. Runs a service.sh to enforce prop values after all services start
        """
        mod_dir = output_dir / "apkre-antidetect"
        mod_dir.mkdir(parents=True, exist_ok=True)

        (mod_dir / "module.prop").write_text(
            "id=apkre-antidetect\n"
            "name=apkre Anti-Detection\n"
            "version=v1.0\n"
            "versionCode=1\n"
            "author=apkre\n"
            "description=Hides emulator artifacts from app detection\n"
        )

        # Overlay: replace init.ranchu.rc with minimal stub
        overlay_dir = mod_dir / "system" / "vendor" / "etc" / "init" / "hw"
        overlay_dir.mkdir(parents=True, exist_ok=True)
        (overlay_dir / "init.ranchu.rc").write_text(
            "# Replaced by apkre anti-detection module\n"
        )

        # post-fs-data.sh
        post_fs = mod_dir / "post-fs-data.sh"
        pfs_lines = [
            "#!/system/bin/sh",
            "# apkre anti-detection: hide emulator device files early in boot",
        ]
        for artifact in cls.EMULATOR_ARTIFACTS:
            pfs_lines.append(f'[ -e "{artifact}" ] && mv "{artifact}" "{artifact}.hidden"')
        pfs_lines.extend([
            "",
            "# Hide goldfish/ranchu platform devices in /sys",
            'for f in /sys/devices/platform/goldfish* /sys/devices/platform/ranchu*; do',
            '  [ -e "$f" ] && chmod 000 "$f" 2>/dev/null',
            "done",
        ])
        post_fs.write_text("\n".join(pfs_lines) + "\n")
        post_fs.chmod(0o755)

        # service.sh — enforce props after boot
        service_sh = mod_dir / "service.sh"
        svc_lines = [
            "#!/system/bin/sh",
            "# apkre anti-detection: enforce props after all services start",
            "",
            "# Delete-then-set critical props",
            "resetprop --delete ro.kernel.qemu; resetprop ro.kernel.qemu 0",
            "resetprop --delete ro.boot.qemu; resetprop ro.boot.qemu 0",
            "resetprop --delete ro.build.tags; resetprop ro.build.tags release-keys",
            "resetprop --delete ro.build.type; resetprop ro.build.type user",
            "resetprop --delete ro.soc.manufacturer; resetprop ro.soc.manufacturer Qualcomm",
            "resetprop --delete ro.soc.model; resetprop ro.soc.model MSM8992",
            "",
            "# Delete emulator-specific props",
        ]
        for prop in cls.PROPS_TO_DELETE:
            svc_lines.append(f"resetprop --delete {prop} 2>/dev/null")
        service_sh.write_text("\n".join(svc_lines) + "\n")
        service_sh.chmod(0o755)

        import shutil
        zip_path = output_dir / "apkre-antidetect-v1.0"
        shutil.make_archive(str(zip_path), "zip", str(mod_dir))
        return Path(f"{zip_path}.zip")
