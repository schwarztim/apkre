"""Generate unique, realistic device identifiers per AVD instance."""
from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass


def _luhn_checksum(partial: str) -> str:
    digits = [int(d) for d in partial]
    for i in range(len(digits) - 1, -1, -2):
        digits[i] *= 2
        if digits[i] > 9:
            digits[i] -= 9
    remainder = sum(digits) % 10
    return str((10 - remainder) % 10)


@dataclass(frozen=True)
class DeviceIdentity:
    instance_id: int
    imei: str
    serial_number: str
    android_id: str
    mac_address: str
    advertising_id: str
    gsf_id: str

    def to_props(self) -> dict[str, str]:
        return {
            "ro.serialno": self.serial_number,
            "persist.sys.wifi.mac": self.mac_address,
            "ro.boot.serialno": self.serial_number,
        }


class IdentityRandomizer:
    NEXUS_5X_TAC = "35390407"

    @classmethod
    def generate(cls, instance_id: int, seed: int | None = None) -> DeviceIdentity:
        rng = random.Random(
            hashlib.sha256(f"{seed or 'apkre'}:{instance_id}".encode()).digest()
        )
        return DeviceIdentity(
            instance_id=instance_id,
            imei=cls._gen_imei(rng),
            serial_number=cls._gen_serial(rng),
            android_id=cls._gen_android_id(rng),
            mac_address=cls._gen_mac(rng),
            advertising_id=cls._gen_uuid4(rng),
            gsf_id=cls._gen_hex(rng, 16),
        )

    @classmethod
    def _gen_imei(cls, rng: random.Random) -> str:
        partial = cls.NEXUS_5X_TAC + "".join(str(rng.randint(0, 9)) for _ in range(6))
        return partial + _luhn_checksum(partial)

    @classmethod
    def _gen_serial(cls, rng: random.Random) -> str:
        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return "".join(rng.choice(chars) for _ in range(12))

    @classmethod
    def _gen_android_id(cls, rng: random.Random) -> str:
        return cls._gen_hex(rng, 16)

    @classmethod
    def _gen_mac(cls, rng: random.Random) -> str:
        octets = [rng.randint(0, 255) for _ in range(6)]
        octets[0] &= 0xFE
        return ":".join(f"{b:02x}" for b in octets)

    @classmethod
    def _gen_uuid4(cls, rng: random.Random) -> str:
        h = cls._gen_hex(rng, 32)
        h = h[:12] + "4" + h[13:16] + rng.choice("89ab") + h[17:]
        return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

    @classmethod
    def _gen_hex(cls, rng: random.Random, length: int) -> str:
        return "".join(rng.choice("0123456789abcdef") for _ in range(length))
