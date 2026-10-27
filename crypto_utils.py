"""
crypto_utils.py  —  Shared cryptographic primitives for Smart-Parking Edge Box Simulation.

Implements: AES-GCM, HMAC, IBE (simulated), ABE (simulated), PRE (proxy re-encryption),
FE (functional encryption), Honey Encryption, SSE (searchable symmetric encryption),
HE (homomorphic encryption – additive Paillier-style), ECC signing, and privacy helpers.
"""

import os, hashlib, hmac as _hmac, json, struct, time, secrets, math
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256, HMAC as CryptoHMAC
from Crypto.Random import get_random_bytes

# ──────────────────────────────────────────────
# 1.  AES-GCM  +  HMAC  (CIA confidentiality)
# ──────────────────────────────────────────────

def aes_encrypt(plaintext: bytes, key: bytes) -> dict:
    """Encrypt with AES-256-GCM and append HMAC-SHA256 tag."""
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    hmac_tag = _hmac.new(key, ciphertext, hashlib.sha256).digest()
    return {"nonce": nonce.hex(), "ct": ciphertext.hex(),
            "gcm_tag": tag.hex(), "hmac": hmac_tag.hex()}

def aes_decrypt(packet: dict, key: bytes) -> bytes:
    """Verify HMAC then decrypt AES-GCM."""
    ct = bytes.fromhex(packet["ct"])
    expected = _hmac.new(key, ct, hashlib.sha256).digest()
    if not _hmac.compare_digest(expected, bytes.fromhex(packet["hmac"])):
        raise ValueError("HMAC verification failed – data tampered!")
    cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(packet["nonce"]))
    return cipher.decrypt_and_verify(ct, bytes.fromhex(packet["gcm_tag"]))


# ──────────────────────────────────────────────
# 2.  ECC  signing  (sensor integrity)
# ──────────────────────────────────────────────

def ecc_keygen():
    key = ECC.generate(curve='P-256')
    return key, key.public_key()

def ecc_sign(private_key, data: bytes) -> bytes:
    h = SHA256.new(data)
    signer = DSS.new(private_key, 'fips-186-3')
    return signer.sign(h)

def ecc_verify(public_key, data: bytes, signature: bytes) -> bool:
    h = SHA256.new(data)
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False


# ──────────────────────────────────────────────
# 3.  IBE  (Identity-Based Encryption) – simulated
# ──────────────────────────────────────────────
# Real IBE needs pairing-based curves.  We simulate the API with
# RSA key derivation keyed by the identity string.

class IBE:
    """Simulated Identity-Based Encryption keyed to parking-lot identity."""

    def __init__(self):
        self._master_key = get_random_bytes(32)

    def _derive(self, identity: str) -> bytes:
        return hashlib.pbkdf2_hmac('sha256', self._master_key, identity.encode(), 100_000)

    def encrypt(self, identity: str, plaintext: bytes) -> dict:
        key = self._derive(identity)
        pkt = aes_encrypt(plaintext, key)
        pkt["identity"] = identity
        return pkt

    def decrypt(self, identity: str, packet: dict) -> bytes:
        key = self._derive(identity)
        return aes_decrypt(packet, key)


# ──────────────────────────────────────────────
# 4.  ABE  (Attribute-Based Encryption) – simulated
# ──────────────────────────────────────────────

class ABE:
    """Ciphertext-policy ABE simulation.  Policy is a set of required attributes."""

    def __init__(self):
        self._master = get_random_bytes(32)

    def _policy_key(self, policy_attrs: frozenset) -> bytes:
        blob = self._master + "|".join(sorted(policy_attrs)).encode()
        return hashlib.sha256(blob).digest()

    def encrypt(self, plaintext: bytes, policy: set) -> dict:
        key = self._policy_key(frozenset(policy))
        pkt = aes_encrypt(plaintext, key)
        pkt["policy"] = sorted(policy)
        return pkt

    def decrypt(self, packet: dict, user_attrs: set) -> bytes:
        policy = frozenset(packet["policy"])
        if not policy.issubset(user_attrs):
            raise PermissionError(f"Attributes {user_attrs} don't satisfy policy {policy}")
        key = self._policy_key(policy)
        return aes_decrypt(packet, key)


# ──────────────────────────────────────────────
# 5.  PRE  (Proxy Re-Encryption) – simulated
# ──────────────────────────────────────────────

class PRE:
    """Simulated uni-directional proxy re-encryption."""

    def __init__(self):
        self._keys: dict[str, bytes] = {}

    def keygen(self, entity: str) -> bytes:
        key = get_random_bytes(32)
        self._keys[entity] = key
        return key

    def encrypt(self, entity: str, plaintext: bytes) -> dict:
        pkt = aes_encrypt(plaintext, self._keys[entity])
        pkt["owner"] = entity
        return pkt

    def re_key(self, src: str, dst: str) -> bytes:
        """Generate re-encryption key  src → dst."""
        rk = bytes(a ^ b for a, b in zip(self._keys[src], self._keys[dst]))
        return rk

    def re_encrypt(self, packet: dict, rk: bytes) -> dict:
        """Re-encrypt a ciphertext under a new key using re-key token."""
        src_key = self._keys[packet["owner"]]
        pt = aes_decrypt(packet, src_key)
        # derive dst key from src_key XOR rk
        dst_key = bytes(a ^ b for a, b in zip(src_key, rk))
        new_pkt = aes_encrypt(pt, dst_key)
        new_pkt["re_encrypted"] = True
        return new_pkt

    def decrypt(self, entity: str, packet: dict) -> bytes:
        return aes_decrypt(packet, self._keys[entity])


# ──────────────────────────────────────────────
# 6.  FE  (Functional Encryption) – simulated
# ──────────────────────────────────────────────

class FE:
    """Functional encryption: returns a *function* of the plaintext, not the plaintext itself."""

    def __init__(self):
        self._master = get_random_bytes(32)

    def issue_func_key(self, func_name: str):
        """Return a function key token (simulated)."""
        return hashlib.sha256(self._master + func_name.encode()).hexdigest()

    def encrypt(self, values: list[int]) -> dict:
        blob = json.dumps(values).encode()
        return aes_encrypt(blob, self._master)

    def compute(self, packet: dict, func_key: str, func_name: str):
        """Decrypt internally and apply the authorised function only."""
        blob = aes_decrypt(packet, self._master)
        values = json.loads(blob)
        if func_name == "occupancy_pct":
            total = len(values)
            occupied = sum(1 for v in values if v == 1)
            return round(occupied / total * 100, 1) if total else 0.0
        elif func_name == "free_ev_count":
            return sum(1 for v in values if v == 0)
        elif func_name == "total_free":
            return sum(1 for v in values if v == 0)
        raise ValueError(f"Unknown function: {func_name}")


# ──────────────────────────────────────────────
# 7.  Honey Encryption  (payment-terminal PINs)
# ──────────────────────────────────────────────

class HoneyEncryption:
    """Honey Encryption: wrong key produces plausible-looking fake data."""

    FAKE_CARDS = [
        "4532-XXXX-XXXX-7891", "5412-XXXX-XXXX-3456",
        "6011-XXXX-XXXX-9012", "3782-XXXX-XXXX-0005",
        "4916-XXXX-XXXX-2345", "5105-XXXX-XXXX-6789",
    ]

    def __init__(self):
        self._seed_map: dict[str, dict] = {}

    def encrypt(self, pin: str, real_card: str) -> dict:
        """Encrypt real_card under the correct PIN."""
        key = hashlib.sha256(pin.encode()).digest()
        ct = aes_encrypt(real_card.encode(), key)
        # store a seed so wrong PINs produce fake but valid-looking cards
        seed = get_random_bytes(16).hex()
        ct["honey_seed"] = seed
        self._seed_map[seed] = {"correct_pin_hash": hashlib.sha256(pin.encode()).hexdigest()}
        return ct

    def decrypt(self, packet: dict, pin_attempt: str) -> str:
        """Decrypt: correct PIN → real card; wrong PIN → plausible fake card."""
        key = hashlib.sha256(pin_attempt.encode()).digest()
        try:
            pt = aes_decrypt(packet, key)
            return pt.decode()
        except Exception:
            # Wrong PIN → generate a deterministic but fake card number
            fake_seed = hashlib.sha256(pin_attempt.encode() + packet["honey_seed"].encode()).digest()
            idx = int.from_bytes(fake_seed[:4], 'big') % len(self.FAKE_CARDS)
            return self.FAKE_CARDS[idx]


# ──────────────────────────────────────────────
# 8.  SSE  (Searchable Symmetric Encryption)
# ──────────────────────────────────────────────

class SSE:
    """Searchable Symmetric Encryption: encrypted index with keyword trapdoors."""

    def __init__(self, key: bytes = None):
        self._key = key or get_random_bytes(32)
        self._enc_index: dict[str, list] = {}   # token → [doc_ids]
        self._documents: dict[str, dict] = {}   # doc_id → encrypted doc

    def _token(self, keyword: str) -> str:
        return _hmac.new(self._key, keyword.lower().encode(), hashlib.sha256).hexdigest()

    def add_document(self, doc_id: str, keywords: list[str], data: dict):
        enc_data = aes_encrypt(json.dumps(data).encode(), self._key)
        self._documents[doc_id] = enc_data
        for kw in keywords:
            tok = self._token(kw)
            self._enc_index.setdefault(tok, []).append(doc_id)

    def trapdoor(self, keyword: str) -> str:
        """Operator generates a trapdoor for a keyword."""
        return self._token(keyword)

    def search(self, trapdoor: str) -> list[dict]:
        doc_ids = self._enc_index.get(trapdoor, [])
        results = []
        for did in doc_ids:
            pt = aes_decrypt(self._documents[did], self._key)
            results.append({"id": did, "data": json.loads(pt)})
        return results


# ──────────────────────────────────────────────
# 9.  HE  (Homomorphic Encryption) – additive
# ──────────────────────────────────────────────

class PaillierLite:
    """Simplified additive HE (Paillier-like) for summing free-spot counts."""

    def __init__(self, bits=512):
        from Crypto.Util.number import getPrime, inverse
        p, q = getPrime(bits // 2), getPrime(bits // 2)
        self.n = p * q
        self.n2 = self.n * self.n
        self.g = self.n + 1
        self._lambda = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
        self._mu = inverse(self._L(pow(self.g, self._lambda, self.n2)), self.n)

    def _L(self, x):
        return (x - 1) // self.n

    def encrypt(self, m: int) -> int:
        r = secrets.randbelow(self.n - 1) + 1
        while math.gcd(r, self.n) != 1:
            r = secrets.randbelow(self.n - 1) + 1
        return (pow(self.g, m, self.n2) * pow(r, self.n, self.n2)) % self.n2

    def decrypt(self, c: int) -> int:
        return (self._L(pow(c, self._lambda, self.n2)) * self._mu) % self.n

    def add(self, c1: int, c2: int) -> int:
        """Homomorphic addition of two ciphertexts."""
        return (c1 * c2) % self.n2


# ──────────────────────────────────────────────
# 10.  Privacy helpers
# ──────────────────────────────────────────────

def hash_plate(plate: str) -> str:
    """One-way hash of license plate (privacy)."""
    return hashlib.sha256(plate.encode()).hexdigest()[:16]

def blur_plate(plate: str) -> str:
    """Partially blur a plate: AB12CD34 → AB**CD**"""
    if len(plate) < 4:
        return "****"
    return plate[:2] + "**" + plate[4:6] + "**" if len(plate) >= 6 else plate[:2] + "****"

def reduce_location(lat: float, lon: float, precision: int = 2) -> tuple:
    return round(lat, precision), round(lon, precision)

def rotate_device_id() -> str:
    """Generate a new temporary device ID."""
    return secrets.token_hex(8)


# ──────────────────────────────────────────────
# 11.  Rate limiter
# ──────────────────────────────────────────────

class RateLimiter:
    """Token-bucket rate limiter that quarantines flooding sources."""

    def __init__(self, max_tokens: int = 10, refill_rate: float = 1.0):
        self.max_tokens = max_tokens
        self.refill_rate = refill_rate          # tokens per second
        self._buckets: dict[str, dict] = {}
        self._quarantined: set[str] = set()

    def _get_bucket(self, source_id: str) -> dict:
        now = time.time()
        if source_id not in self._buckets:
            self._buckets[source_id] = {"tokens": self.max_tokens, "last": now}
        b = self._buckets[source_id]
        elapsed = now - b["last"]
        b["tokens"] = min(self.max_tokens, b["tokens"] + elapsed * self.refill_rate)
        b["last"] = now
        return b

    def allow(self, source_id: str) -> bool:
        if source_id in self._quarantined:
            return False
        b = self._get_bucket(source_id)
        if b["tokens"] >= 1:
            b["tokens"] -= 1
            return True
        # Quarantine the flooding source
        self._quarantined.add(source_id)
        return False

    def is_quarantined(self, source_id: str) -> bool:
        return source_id in self._quarantined

    def release(self, source_id: str):
        self._quarantined.discard(source_id)
        if source_id in self._buckets:
            self._buckets[source_id]["tokens"] = self.max_tokens
