"""
parking_edge.py  —  Parking Edge Server.

Receives encrypted camera/sensor data, stores ciphertext, and provides:
• IBE decryption by lot identity
• ABE policy-gated access ("ParkingAttendant AND Lot3")
• PRE re-keying for city-inspector process
• FE: returns occupancy % or free-EV count (not raw data)
• SSE: keyword-searchable encrypted event index
• HE: Paillier-based free-spot summation across lots
• Honey Encryption on payment-terminal PINs
• JWT tokens for city-payment and ticket handover
• Rate-limiter that quarantines flooding cameras
• Privacy: plate hashing/blurring, location reduction, temp IDs
"""

import json, time, hashlib, secrets
import jwt as pyjwt

from crypto_utils import (
    aes_decrypt, ecc_verify,
    IBE, ABE, PRE, FE, HoneyEncryption, SSE, PaillierLite,
    RateLimiter, hash_plate, blur_plate, reduce_location, rotate_device_id,
    get_random_bytes
)


class ParkingEdgeServer:
    """Central edge-box server for a smart-parking deployment."""

    def __init__(self, aes_key: bytes, lot_id: str = "LOT-3"):
        self.lot_id = lot_id
        self._aes_key = aes_key

        # Crypto subsystems
        self.ibe = IBE()
        self.abe = ABE()
        self.pre = PRE()
        self.fe = FE()
        self.honey = HoneyEncryption()
        self.sse = SSE(key=aes_key)
        self.he = PaillierLite(bits=512)
        self.limiter = RateLimiter(max_tokens=10, refill_rate=2.0)

        # PRE: register operator & inspector
        self.pre.keygen("operator")
        self.pre.keygen("city-inspector")

        # Storage
        self._stored_ct: list[dict] = []          # raw ciphertext store
        self._events: list[dict] = []             # decrypted events (in-memory)

        # JWT secret
        self._jwt_secret = secrets.token_hex(32)

    # ──────── Ingest ────────

    def ingest(self, packet: dict, pub_key=None) -> dict:
        """Receive an encrypted packet from a camera or sensor."""
        src = packet.get("camera_id") or packet.get("sensor_id") or "unknown"

        # Rate-limit check
        if not self.limiter.allow(src):
            return {"status": "QUARANTINED", "source": src,
                    "msg": f"⚠️  {src} quarantined – flooding detected!"}

        # Optional ECC signature verification
        if pub_key and "ecc_signature" in packet:
            ct_bytes = bytes.fromhex(packet["encrypted"]["ct"])
            sig = bytes.fromhex(packet["ecc_signature"])
            if not ecc_verify(pub_key, ct_bytes, sig):
                return {"status": "REJECTED", "source": src,
                        "msg": "ECC signature verification failed."}

        # Store ciphertext (edge stores encrypted, never plaintext at rest)
        entry = {
            "id": f"EVT-{len(self._stored_ct)+1:05d}",
            "source": src,
            "lot_id": packet.get("lot_id", self.lot_id),
            "received_at": time.time(),
            "ciphertext": packet["encrypted"],
        }
        self._stored_ct.append(entry)

        # Decrypt for internal indexing (edge has the key)
        try:
            pt = aes_decrypt(packet["encrypted"], self._aes_key)
            data = json.loads(pt)
            self._events.append({"id": entry["id"], **data})

            # Build SSE index keywords
            keywords = [src, packet.get("lot_id", ""), entry["id"]]
            if "plate_hash" in data:
                keywords.append(data["plate_hash"])
            if "occupied" in data:
                keywords.append("occupied" if data["occupied"] else "free")
            self.sse.add_document(entry["id"], keywords, data)
        except Exception:
            pass   # ciphertext stored even if we can't index it

        return {"status": "OK", "event_id": entry["id"], "source": src}

    # ──────── IBE ────────

    def ibe_encrypt(self, data: dict) -> dict:
        """Encrypt data under lot identity (IBE)."""
        return self.ibe.encrypt(self.lot_id, json.dumps(data).encode())

    def ibe_decrypt(self, packet: dict) -> dict:
        pt = self.ibe.decrypt(self.lot_id, packet)
        return json.loads(pt)

    # ──────── ABE ────────

    def abe_encrypt(self, data: dict, policy: set = None) -> dict:
        """Encrypt with ABE policy (default: ParkingAttendant AND Lot3)."""
        policy = policy or {"ParkingAttendant", "Lot3"}
        return self.abe.encrypt(json.dumps(data).encode(), policy)

    def abe_decrypt(self, packet: dict, user_attrs: set) -> dict:
        pt = self.abe.decrypt(packet, user_attrs)
        return json.loads(pt)

    # ──────── PRE ────────

    def pre_encrypt_for_operator(self, data: dict) -> dict:
        return self.pre.encrypt("operator", json.dumps(data).encode())

    def pre_rekey_to_inspector(self) -> bytes:
        """Operator issues re-encryption key to city-inspector."""
        return self.pre.re_key("operator", "city-inspector")

    def pre_re_encrypt(self, packet: dict, rk: bytes) -> dict:
        return self.pre.re_encrypt(packet, rk)

    def pre_decrypt_inspector(self, packet: dict) -> dict:
        pt = self.pre.decrypt("city-inspector", packet)
        return json.loads(pt)

    # ──────── FE ────────

    def fe_occupancy_pct(self, occupancy_vector: list[int]) -> float:
        """Encrypt occupancy vector and compute occupancy % via FE (no raw data exposed)."""
        ct = self.fe.encrypt(occupancy_vector)
        fk = self.fe.issue_func_key("occupancy_pct")
        return self.fe.compute(ct, fk, "occupancy_pct")

    def fe_free_ev_count(self, ev_vector: list[int]) -> int:
        ct = self.fe.encrypt(ev_vector)
        fk = self.fe.issue_func_key("free_ev_count")
        return self.fe.compute(ct, fk, "free_ev_count")

    # ──────── Honey Encryption ────────

    def honey_encrypt_pin(self, pin: str, real_card: str) -> dict:
        return self.honey.encrypt(pin, real_card)

    def honey_decrypt_pin(self, packet: dict, pin_attempt: str) -> str:
        return self.honey.decrypt(packet, pin_attempt)

    # ──────── SSE search ────────

    def search_events(self, keyword: str) -> list[dict]:
        td = self.sse.trapdoor(keyword)
        return self.sse.search(td)

    # ──────── HE free-spot sum ────────

    def he_sum_free_spots(self, counts: list[int]) -> int:
        """Homomorphically sum free-spot counts across multiple edge boxes."""
        if not counts:
            return 0
        enc = [self.he.encrypt(c) for c in counts]
        total_enc = enc[0]
        for c in enc[1:]:
            total_enc = self.he.add(total_enc, c)
        return self.he.decrypt(total_enc)

    # ──────── JWT / Auth ────────

    def issue_operator_jwt(self, operator_id: str) -> str:
        """Single-domain operator JWT."""
        payload = {
            "sub": operator_id, "role": "operator",
            "domain": self.lot_id, "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        }
        return pyjwt.encode(payload, self._jwt_secret, algorithm="HS256")

    def issue_city_payment_jwt(self, user_id: str) -> str:
        """City-wide payment JWT."""
        payload = {
            "sub": user_id, "role": "city-payment",
            "scope": "payment:read payment:write",
            "iat": int(time.time()),
            "exp": int(time.time()) + 1800,
        }
        return pyjwt.encode(payload, self._jwt_secret, algorithm="HS256")

    def issue_ticket_handover(self, ticket_id: str, mobile_user: str) -> str:
        """Ticket handover token for mobile payment apps."""
        payload = {
            "sub": mobile_user, "role": "mobile-app",
            "ticket": ticket_id,
            "handover": True,
            "iat": int(time.time()),
            "exp": int(time.time()) + 900,
        }
        return pyjwt.encode(payload, self._jwt_secret, algorithm="HS256")

    def verify_jwt(self, token: str) -> dict:
        return pyjwt.decode(token, self._jwt_secret, algorithms=["HS256"])

    # ──────── Helpers ────────

    def get_stored_count(self) -> int:
        return len(self._stored_ct)

    def get_event_count(self) -> int:
        return len(self._events)
