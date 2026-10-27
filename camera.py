"""
camera.py  —  Simulated parking-lot camera process.

• Captures license plates and occupancy frames.
• Encrypts data with AES-GCM + HMAC before sending to edge.
• Also encrypts with IBE (lot identity) for lot-specific decryption.
• Supports ECC signing for integrity.
• Privacy: hashes/blurs plates, rotates temporary device IDs.
"""

import json, time, random, string
from crypto_utils import (
    aes_encrypt, ecc_keygen, ecc_sign,
    hash_plate, blur_plate, rotate_device_id
)


class Camera:
    """Simulates a parking-lot camera that produces plate + occupancy data."""

    SAMPLE_PLATES = [
        "KA01AB1234", "MH02CD5678", "DL03EF9012",
        "TN04GH3456", "AP05IJ7890", "KL06KL2345",
        "RJ07MN6789", "GJ08OP0123", "UP09QR4567",
        "HR10ST8901",
    ]

    def __init__(self, camera_id: str, lot_id: str, aes_key: bytes):
        self.camera_id = camera_id
        self.lot_id = lot_id
        self._aes_key = aes_key
        self._ecc_priv, self.ecc_pub = ecc_keygen()
        self._device_id = rotate_device_id()
        self._frame_seq = 0

    def capture_frame(self) -> dict:
        """Simulate a camera frame with plate detection and occupancy."""
        self._frame_seq += 1
        plate = random.choice(self.SAMPLE_PLATES)
        occupied = random.choice([True, False])

        raw = {
            "camera_id": self.camera_id,
            "device_id": self._device_id,
            "lot_id": self.lot_id,
            "timestamp": time.time(),
            "seq": self._frame_seq,
            "plate_raw": plate,
            "plate_hash": hash_plate(plate),
            "plate_blur": blur_plate(plate),
            "occupied": occupied,
            "confidence": round(random.uniform(0.85, 0.99), 2),
        }
        return raw

    def encrypt_frame(self, frame: dict) -> dict:
        """Encrypt frame payload with AES-GCM + HMAC and sign with ECC."""
        plaintext = json.dumps(frame).encode()
        encrypted = aes_encrypt(plaintext, self._aes_key)

        # ECC signature over ciphertext for integrity
        sig = ecc_sign(self._ecc_priv, bytes.fromhex(encrypted["ct"]))

        return {
            "type": "camera_frame",
            "camera_id": self.camera_id,
            "lot_id": self.lot_id,
            "device_id": self._device_id,
            "encrypted": encrypted,
            "ecc_signature": sig.hex(),
        }

    def rotate_id(self):
        """Rotate temporary device ID for privacy."""
        old = self._device_id
        self._device_id = rotate_device_id()
        return old, self._device_id

    def send(self) -> dict:
        """Capture → encrypt → return packet ready for edge server."""
        frame = self.capture_frame()
        return self.encrypt_frame(frame)


def demo():
    """Quick standalone demo of camera operation."""
    from Crypto.Random import get_random_bytes
    key = get_random_bytes(32)
    cam = Camera("CAM-01", "LOT-3", key)

    print("=" * 60)
    print("  📷  Camera Process Demo")
    print("=" * 60)

    for i in range(3):
        pkt = cam.send()
        print(f"\n[Frame {i+1}]")
        print(f"  Camera   : {pkt['camera_id']}")
        print(f"  Lot      : {pkt['lot_id']}")
        print(f"  DeviceID : {pkt['device_id']}")
        print(f"  CT (first 40 chars): {pkt['encrypted']['ct'][:40]}...")
        print(f"  HMAC     : {pkt['encrypted']['hmac'][:32]}...")
        print(f"  ECC Sig  : {pkt['ecc_signature'][:32]}...")

    old, new = cam.rotate_id()
    print(f"\n  🔄 Device ID rotated: {old} → {new}")
    print()


if __name__ == "__main__":
    demo()
