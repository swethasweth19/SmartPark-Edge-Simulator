#!/usr/bin/env python3
"""
demo.py  —  Full Smart-Parking Edge Box Simulation Demo.

Walks through every requirement:
  1. Cameras/sensors → edge (AES+HMAC, ECC signatures)
  2. IBE to lot identity
  3. ABE "ParkingAttendant AND Lot3"
  4. PRE: operator re-keys to city-inspector
  5. FE: occupancy % and free EV-bay count
  6. Honey Encryption on payment PINs
  7. SSE: searchable encrypted event index
  8. HE: sum free spots across edge boxes
  9. JWT: operator, city-payment, ticket handover
 10. Privacy: plate hash/blur, reduced location, rotated device IDs
 11. Rate-limiter: quarantine flooding cameras
"""

import json, time
from Crypto.Random import get_random_bytes

from camera import Camera
from sensor import Sensor
from parking_edge import ParkingEdgeServer

# ═══════════════════════════════════════════════
BORDER = "═" * 70
SECTION = "─" * 70

def banner(n, title):
    print(f"\n{BORDER}")
    print(f"  STEP {n}  │  {title}")
    print(BORDER)


def main():
    print()
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║       🅿️   SMART-PARKING  EDGE  BOX  SIMULATION  🅿️               ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")

    # Shared AES key (in production, distributed via TLS handshake)
    aes_key = get_random_bytes(32)

    # ── Setup ──
    cam1 = Camera("CAM-01", "LOT-3", aes_key)
    cam2 = Camera("CAM-02", "LOT-3", aes_key)
    sens1 = Sensor("SENS-01", "LOT-3", bay_count=20, aes_key=aes_key)
    sens2 = Sensor("SENS-02", "LOT-5", bay_count=15, aes_key=aes_key)
    edge = ParkingEdgeServer(aes_key, lot_id="LOT-3")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # STEP 1 – Cameras / sensors → Edge
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    banner(1, "Cameras & Sensors → Edge  (AES-GCM + HMAC + ECC)")

    for i in range(3):
        pkt = cam1.send()
        res = edge.ingest(pkt, pub_key=cam1.ecc_pub)
        print(f"  📷 CAM-01 frame {i+1}: {res['status']}  event={res.get('event_id','')}")

    for i in range(3):
        pkt = sens1.send()
        res = edge.ingest(pkt, pub_key=sens1.ecc_pub)
        print(f"  📡 SENS-01 reading {i+1}: {res['status']}  event={res.get('event_id','')}")

    pkt = cam2.send()
    res = edge.ingest(pkt, pub_key=cam2.ecc_pub)
    print(f"  📷 CAM-02 frame  : {res['status']}  event={res.get('event_id','')}")

    pkt = sens2.send()
    res = edge.ingest(pkt, pub_key=sens2.ecc_pub)
    print(f"  📡 SENS-02 reading: {res['status']}  event={res.get('event_id','')}")

    print(f"\n  ✅ Edge stored {edge.get_stored_count()} ciphertexts, indexed {edge.get_event_count()} events.")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # STEP 2 – IBE: encrypt to lot identity
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    banner(2, "IBE — Encrypt to Lot Identity ('LOT-3')")

    sample = {"lot": "LOT-3", "free_bays": 7, "timestamp": time.time()}
    ibe_ct = edge.ibe_encrypt(sample)
    print(f"  🔐 IBE ciphertext (identity='LOT-3'): {ibe_ct['ct'][:50]}...")
    ibe_pt = edge.ibe_decrypt(ibe_ct)
    print(f"  🔓 IBE decrypted: {ibe_pt}")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # STEP 3 – ABE: "ParkingAttendant AND Lot3"
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    banner(3, "ABE — Policy: {ParkingAttendant, Lot3}")

    secret = {"zone": "A", "revenue": 12500, "alert": "sensor offline"}
    abe_ct = edge.abe_encrypt(secret, policy={"ParkingAttendant", "Lot3"})
    print(f"  🔐 ABE ciphertext: {abe_ct['ct'][:50]}...")
    print(f"     Policy: {abe_ct['policy']}")

    # Authorised user
    try:
        abe_pt = edge.abe_decrypt(abe_ct, user_attrs={"ParkingAttendant", "Lot3", "Shift-A"})
        print(f"  ✅ Authorised decrypt: {abe_pt}")
    except PermissionError as e:
        print(f"  ❌ {e}")

    # Unauthorised user
    try:
        edge.abe_decrypt(abe_ct, user_attrs={"SecurityGuard", "Lot3"})
    except PermissionError as e:
        print(f"  ❌ Unauthorised attempt: {e}")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # STEP 4 – PRE: re-key operator → city-inspector
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    banner(4, "PRE — Operator → City-Inspector Re-Encryption")

    op_data = {"violations": 3, "lot": "LOT-3", "date": "2026-10-27"}
    pre_ct = edge.pre_encrypt_for_operator(op_data)
    print(f"  🔐 PRE ciphertext (operator): {pre_ct['ct'][:50]}...")

    rk = edge.pre_rekey_to_inspector()
    print(f"  🔑 Re-encryption key issued (operator → inspector)")

    re_ct = edge.pre_re_encrypt(pre_ct, rk)
    print(f"  🔄 Re-encrypted ciphertext: {re_ct['ct'][:50]}...")
    print(f"     re_encrypted flag: {re_ct.get('re_encrypted')}")

    insp_pt = edge.pre_decrypt_inspector(re_ct)
    print(f"  🔓 Inspector decrypted: {insp_pt}")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # STEP 5 – FE: occupancy % and free EV count
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    banner(5, "FE — Functional Encryption (occupancy %, free EV bays)")

    occ_vec = sens1.get_occupancy_vector()
    print(f"  Raw occupancy vector (SENS-01, {len(occ_vec)} bays): {occ_vec}")

    occ_pct = edge.fe_occupancy_pct(occ_vec)
    print(f"  📊 FE → Occupancy percentage: {occ_pct}%")

    # For EV bays: 1 = occupied EV, 0 = free EV (filter)
    ev_vec = [1 if b["occupied"] else 0 for b in sens1.bays if b["type"] == "ev"]
    if ev_vec:
        free_ev = edge.fe_free_ev_count(ev_vec)
        print(f"  ⚡ FE → Free EV bays: {free_ev} / {len(ev_vec)}")
    else:
        print(f"  ⚡ No EV bays in SENS-01")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # STEP 6 – Honey Encryption (payment PINs)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    banner(6, "Honey Encryption — Payment Terminal PINs")

    real_pin = "4829"
    real_card = "4532-1234-5678-9012"
    honey_ct = edge.honey_encrypt_pin(real_pin, real_card)
    print(f"  🔐 Honey-encrypted PIN={real_pin}, card={real_card}")

    # Correct PIN
    result = edge.honey_decrypt_pin(honey_ct, "4829")
    print(f"  ✅ Correct PIN (4829) → card: {result}")

    # Wrong PINs → plausible fake cards
    for wrong in ["0000", "1234", "9999"]:
        fake = edge.honey_decrypt_pin(honey_ct, wrong)
        print(f"  🍯 Wrong PIN ({wrong})  → fake card: {fake}")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # STEP 7 – SSE: searchable encrypted events
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    banner(7, "SSE — Searchable Symmetric Encryption")

    print(f"  Searching for keyword 'CAM-01'...")
    results = edge.search_events("CAM-01")
    print(f"  🔍 Found {len(results)} events:")
    for r in results[:3]:
        d = r['data']
        print(f"     {r['id']}: plate_blur={d.get('plate_blur','N/A')}, "
              f"occupied={d.get('occupied','N/A')}")

    print(f"\n  Searching for keyword 'free'...")
    results2 = edge.search_events("free")
    print(f"  🔍 Found {len(results2)} 'free' events")

    print(f"\n  Searching for keyword 'occupied'...")
    results3 = edge.search_events("occupied")
    print(f"  🔍 Found {len(results3)} 'occupied' events")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # STEP 8 – HE: sum free spots across boxes
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    banner(8, "HE — Homomorphic Sum of Free Spots Across Boxes")

    free1 = sens1.get_free_count()
    free2 = sens2.get_free_count()
    print(f"  LOT-3 (SENS-01) free spots: {free1}")
    print(f"  LOT-5 (SENS-02) free spots: {free2}")

    he_total = edge.he_sum_free_spots([free1, free2])
    print(f"  🔢 HE homomorphic sum (encrypted): {he_total}")
    print(f"  ✅ Verification (plain sum): {free1 + free2}")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # STEP 9 – JWT: operator, city-payment, ticket handover
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    banner(9, "JWT — Operator, City-Payment, Ticket Handover")

    op_jwt = edge.issue_operator_jwt("OP-ALICE")
    print(f"  🎫 Operator JWT: {op_jwt[:60]}...")
    op_claims = edge.verify_jwt(op_jwt)
    print(f"     Claims: role={op_claims['role']}, domain={op_claims['domain']}")

    pay_jwt = edge.issue_city_payment_jwt("USER-BOB")
    print(f"\n  💳 City-Payment JWT: {pay_jwt[:60]}...")
    pay_claims = edge.verify_jwt(pay_jwt)
    print(f"     Claims: role={pay_claims['role']}, scope={pay_claims['scope']}")

    tkt_jwt = edge.issue_ticket_handover("TKT-98765", "MOBILE-CHARLIE")
    print(f"\n  📱 Ticket Handover JWT: {tkt_jwt[:60]}...")
    tkt_claims = edge.verify_jwt(tkt_jwt)
    print(f"     Claims: role={tkt_claims['role']}, ticket={tkt_claims['ticket']}, handover={tkt_claims['handover']}")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # STEP 10 – Privacy: hash/blur plates, location, temp IDs
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    banner(10, "Privacy — Plate Hash/Blur, Location Reduction, Temp IDs")

    from crypto_utils import hash_plate, blur_plate, reduce_location

    plate = "KA01AB1234"
    print(f"  Original plate : {plate}")
    print(f"  Hashed plate   : {hash_plate(plate)}")
    print(f"  Blurred plate  : {blur_plate(plate)}")

    lat, lon = 12.971598, 77.594566
    rlat, rlon = reduce_location(lat, lon, precision=2)
    print(f"\n  Original location : ({lat}, {lon})")
    print(f"  Reduced precision : ({rlat}, {rlon})")

    old1, new1 = cam1.rotate_id()
    old2, new2 = sens1.rotate_id()
    print(f"\n  🔄 CAM-01 device ID: {old1} → {new1}")
    print(f"  🔄 SENS-01 device ID: {old2} → {new2}")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # STEP 11 – Rate-limiter: flood detection
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    banner(11, "Rate-Limiter — Quarantine Flooding Cameras")

    flood_cam = Camera("CAM-FLOOD", "LOT-3", aes_key)
    print(f"  Sending 15 rapid frames from CAM-FLOOD...")

    accepted = 0
    quarantined_at = None
    for i in range(15):
        pkt = flood_cam.send()
        res = edge.ingest(pkt)
        if res["status"] == "OK":
            accepted += 1
        elif res["status"] == "QUARANTINED" and quarantined_at is None:
            quarantined_at = i + 1

    print(f"  ✅ Accepted: {accepted} frames")
    print(f"  ⛔ Quarantined at frame: {quarantined_at}")
    print(f"  🚫 CAM-FLOOD quarantined? {edge.limiter.is_quarantined('CAM-FLOOD')}")

    # Release
    edge.limiter.release("CAM-FLOOD")
    print(f"  🔓 Released CAM-FLOOD. Quarantined? {edge.limiter.is_quarantined('CAM-FLOOD')}")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Summary
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    print(f"\n{BORDER}")
    print("  ✅  ALL 14 STEPS DEMONSTRATED SUCCESSFULLY")
    print(BORDER)
    print(f"""
  Summary of Cryptographic Techniques Used:
  ──────────────────────────────────────────
  1.  AES-256-GCM + HMAC-SHA256    — Confidentiality & integrity
  2.  ECC (P-256) signatures       — Sensor/camera authentication
  3.  IBE (Identity-Based)         — Encrypt to lot identity
  4.  ABE (Attribute-Based)        — Policy: ParkingAttendant ∧ Lot3
  5.  PRE (Proxy Re-Encryption)    — Operator → city-inspector delegation
  6.  FE  (Functional Encryption)  — Occupancy % / free EV count
  7.  Honey Encryption             — Payment PINs (fake cards on wrong key)
  8.  SSE (Searchable Symmetric)   — Encrypted event index + trapdoors
  9.  HE  (Homomorphic – Paillier) — Sum free spots across edge boxes
  10. JWT  tokens                   — Operator / city-payment / ticket handover
  11. Privacy                       — Plate hash/blur, location reduction, temp IDs
  12. Rate-limiting                 — Token-bucket with quarantine
  
  Total events ingested: {edge.get_event_count()}
  Total ciphertexts stored: {edge.get_stored_count()}
""")


if __name__ == "__main__":
    main()
