"""
sensor.py  —  Simulated parking-bay sensor process.

• Reports per-bay occupancy (occupied / free / EV-bay status).
• Encrypts with AES-GCM + HMAC  (sensors limited to AES + ECC per spec).
• ECC signing for integrity.
• Supports reduced-precision location and temporary device IDs.
"""

import json, time, random
from crypto_utils import (
    aes_encrypt, ecc_keygen, ecc_sign,
    reduce_location, rotate_device_id
)


class Sensor:
    """Simulates an IoT parking-bay sensor."""

    BAY_TYPES = ["standard", "standard", "standard", "ev", "disabled"]

    def __init__(self, sensor_id: str, lot_id: str, bay_count: int,
                 aes_key: bytes, lat: float = 12.97, lon: float = 77.59):
        self.sensor_id = sensor_id
        self.lot_id = lot_id
        self.bay_count = bay_count
        self._aes_key = aes_key
        self._ecc_priv, self.ecc_pub = ecc_keygen()
        self._device_id = rotate_device_id()
        self._lat = lat
        self._lon = lon
        self._seq = 0

        # Initialise bays
        self.bays = []
        for i in range(bay_count):
            self.bays.append({
                "bay_id": f"{lot_id}-B{i+1:03d}",
                "type": random.choice(self.BAY_TYPES),
                "occupied": random.choice([True, False]),
            })

    def read_bays(self) -> dict:
        """Simulate a sensor reading — randomly toggle some bays."""
        self._seq += 1
        for bay in self.bays:
            if random.random() < 0.15:       # 15 % chance of state change
                bay["occupied"] = not bay["occupied"]

        lat_r, lon_r = reduce_location(self._lat, self._lon, precision=2)

        reading = {
            "sensor_id": self.sensor_id,
            "device_id": self._device_id,
            "lot_id": self.lot_id,
            "timestamp": time.time(),
            "seq": self._seq,
            "location": {"lat": lat_r, "lon": lon_r},
            "bays": [dict(b) for b in self.bays],
            "total": self.bay_count,
            "free": sum(1 for b in self.bays if not b["occupied"]),
            "free_ev": sum(1 for b in self.bays if not b["occupied"] and b["type"] == "ev"),
        }
        return reading

    def encrypt_reading(self, reading: dict) -> dict:
        """Encrypt sensor reading with AES + ECC (per spec constraints)."""
        plaintext = json.dumps(reading).encode()
        encrypted = aes_encrypt(plaintext, self._aes_key)
        sig = ecc_sign(self._ecc_priv, bytes.fromhex(encrypted["ct"]))

        return {
            "type": "sensor_reading",
            "sensor_id": self.sensor_id,
            "lot_id": self.lot_id,
            "device_id": self._device_id,
            "encrypted": encrypted,
            "ecc_signature": sig.hex(),
        }

    def rotate_id(self):
        old = self._device_id
        self._device_id = rotate_device_id()
        return old, self._device_id

    def send(self) -> dict:
        """Read → encrypt → return packet."""
        reading = self.read_bays()
        return self.encrypt_reading(reading)

    def get_occupancy_vector(self) -> list[int]:
        """Return a binary vector: 1 = occupied, 0 = free (for FE / HE)."""
        return [1 if b["occupied"] else 0 for b in self.bays]

    def get_free_count(self) -> int:
        return sum(1 for b in self.bays if not b["occupied"])

    def get_free_ev_count(self) -> int:
        return sum(1 for b in self.bays if not b["occupied"] and b["type"] == "ev")


def demo():
    """Quick standalone demo of sensor operation."""
    from Crypto.Random import get_random_bytes
    key = get_random_bytes(32)
    sensor = Sensor("SENS-01", "LOT-3", bay_count=10, aes_key=key)

    print("=" * 60)
    print("  🅿️  Sensor Process Demo")
    print("=" * 60)

    for i in range(3):
        pkt = sensor.send()
        reading = sensor.read_bays()
        print(f"\n[Reading {i+1}]")
        print(f"  Sensor   : {pkt['sensor_id']}")
        print(f"  Lot      : {pkt['lot_id']}")
        print(f"  Free     : {reading['free']} / {reading['total']}")
        print(f"  Free EV  : {reading['free_ev']}")
        print(f"  CT (40)  : {pkt['encrypted']['ct'][:40]}...")
        print(f"  ECC Sig  : {pkt['ecc_signature'][:32]}...")

    old, new = sensor.rotate_id()
    print(f"\n  🔄 Device ID rotated: {old} → {new}")
    print()


if __name__ == "__main__":
    demo()
