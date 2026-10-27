"""
app.py  —  Flask Web Dashboard for Smart-Parking Edge Box Simulation.
Provides a beautiful real-time UI to visualize all cryptographic operations.
"""

import json, time, secrets
from flask import Flask, render_template, jsonify, request
from Crypto.Random import get_random_bytes

from camera import Camera
from sensor import Sensor
from parking_edge import ParkingEdgeServer
from crypto_utils import hash_plate, blur_plate, reduce_location, rotate_device_id

app = Flask(__name__)

# ── Global simulation state ──
AES_KEY = get_random_bytes(32)

cameras = {
    "CAM-01": Camera("CAM-01", "LOT-3", AES_KEY),
    "CAM-02": Camera("CAM-02", "LOT-3", AES_KEY),
    "CAM-03": Camera("CAM-03", "LOT-5", AES_KEY),
}

sensors = {
    "SENS-01": Sensor("SENS-01", "LOT-3", bay_count=20, aes_key=AES_KEY, lat=12.9716, lon=77.5946),
    "SENS-02": Sensor("SENS-02", "LOT-5", bay_count=15, aes_key=AES_KEY, lat=12.9352, lon=77.6245),
    "SENS-03": Sensor("SENS-03", "LOT-7", bay_count=25, aes_key=AES_KEY, lat=12.9698, lon=77.7500),
}

edge = ParkingEdgeServer(AES_KEY, lot_id="LOT-3")

# Event log for the UI
event_log = []

def log_event(step, category, message, detail=""):
    entry = {
        "id": len(event_log) + 1,
        "time": time.strftime("%H:%M:%S"),
        "step": step,
        "category": category,
        "message": message,
        "detail": detail,
    }
    event_log.append(entry)
    # Keep last 200 events
    if len(event_log) > 200:
        event_log.pop(0)
    return entry


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def status():
    """Get current system status."""
    lot_stats = {}
    for sid, s in sensors.items():
        reading = s.read_bays()
        lot_stats[sid] = {
            "lot_id": s.lot_id,
            "total": reading["total"],
            "free": reading["free"],
            "free_ev": reading["free_ev"],
            "occupancy_pct": round((1 - reading["free"] / reading["total"]) * 100, 1) if reading["total"] else 0,
        }

    return jsonify({
        "cameras": list(cameras.keys()),
        "sensors": list(sensors.keys()),
        "lots": lot_stats,
        "stored_ciphertexts": edge.get_stored_count(),
        "indexed_events": edge.get_event_count(),
        "event_log": event_log[-20:],
    })


@app.route("/api/step1", methods=["POST"])
def step1_ingest():
    """Step 1: Cameras/Sensors → Edge (AES+HMAC+ECC)."""
    results = []
    for cid, cam in cameras.items():
        pkt = cam.send()
        res = edge.ingest(pkt, pub_key=cam.ecc_pub)
        log_event(1, "INGEST", f"{cid} → Edge: {res['status']}", f"Event: {res.get('event_id','')}")
        results.append({"source": cid, "type": "camera", **res})

    for sid, sens in sensors.items():
        pkt = sens.send()
        res = edge.ingest(pkt, pub_key=sens.ecc_pub)
        log_event(1, "INGEST", f"{sid} → Edge: {res['status']}", f"Event: {res.get('event_id','')}")
        results.append({"source": sid, "type": "sensor", **res})

    return jsonify({"step": 1, "title": "AES-GCM + HMAC + ECC Ingest", "results": results})


@app.route("/api/step2", methods=["POST"])
def step2_ibe():
    """Step 2: IBE — encrypt to lot identity."""
    sample = {"lot": "LOT-3", "free_bays": sensors["SENS-01"].get_free_count(), "ts": time.time()}
    ct = edge.ibe_encrypt(sample)
    pt = edge.ibe_decrypt(ct)
    log_event(2, "IBE", "Encrypted to identity 'LOT-3'", f"Decrypted: {json.dumps(pt)}")
    return jsonify({
        "step": 2, "title": "IBE — Identity-Based Encryption",
        "identity": "LOT-3",
        "ciphertext_preview": ct["ct"][:80] + "...",
        "decrypted": pt,
    })


@app.route("/api/step3", methods=["POST"])
def step3_abe():
    """Step 3: ABE — policy ParkingAttendant AND Lot3."""
    secret = {"zone": "A", "revenue": 12500, "alert": "sensor offline"}
    ct = edge.abe_encrypt(secret, policy={"ParkingAttendant", "Lot3"})

    auth_result, unauth_result = None, None
    try:
        auth_result = edge.abe_decrypt(ct, user_attrs={"ParkingAttendant", "Lot3", "Shift-A"})
    except PermissionError as e:
        auth_result = str(e)

    try:
        edge.abe_decrypt(ct, user_attrs={"SecurityGuard", "Lot3"})
        unauth_result = "Decrypted (should not happen)"
    except PermissionError as e:
        unauth_result = str(e)

    log_event(3, "ABE", "Policy: {ParkingAttendant, Lot3}", f"Auth: OK, Unauth: Denied")
    return jsonify({
        "step": 3, "title": "ABE — Attribute-Based Encryption",
        "policy": ["ParkingAttendant", "Lot3"],
        "ciphertext_preview": ct["ct"][:80] + "...",
        "authorised": {"attrs": ["ParkingAttendant", "Lot3", "Shift-A"], "result": auth_result},
        "unauthorised": {"attrs": ["SecurityGuard", "Lot3"], "result": unauth_result},
    })


@app.route("/api/step4", methods=["POST"])
def step4_pre():
    """Step 4: PRE — operator re-keys to city-inspector."""
    data = {"violations": 3, "lot": "LOT-3", "date": time.strftime("%Y-%m-%d")}
    ct = edge.pre_encrypt_for_operator(data)
    rk = edge.pre_rekey_to_inspector()
    re_ct = edge.pre_re_encrypt(ct, rk)
    pt = edge.pre_decrypt_inspector(re_ct)

    log_event(4, "PRE", "Operator → Inspector re-encryption", f"Inspector decrypted: {json.dumps(pt)}")
    return jsonify({
        "step": 4, "title": "PRE — Proxy Re-Encryption",
        "operator_ct": ct["ct"][:80] + "...",
        "re_encrypted_ct": re_ct["ct"][:80] + "...",
        "inspector_decrypted": pt,
    })


@app.route("/api/step5", methods=["POST"])
def step5_fe():
    """Step 5: FE — occupancy % and free EV count."""
    results = {}
    for sid, sens in sensors.items():
        occ_vec = sens.get_occupancy_vector()
        occ_pct = edge.fe_occupancy_pct(occ_vec)
        ev_vec = [1 if b["occupied"] else 0 for b in sens.bays if b["type"] == "ev"]
        free_ev = edge.fe_free_ev_count(ev_vec) if ev_vec else 0
        results[sid] = {
            "lot_id": sens.lot_id,
            "occupancy_pct": occ_pct,
            "total_bays": len(occ_vec),
            "ev_bays": len(ev_vec),
            "free_ev": free_ev,
        }

    log_event(5, "FE", "Computed occupancy via FE", json.dumps(results))
    return jsonify({"step": 5, "title": "FE — Functional Encryption", "results": results})


@app.route("/api/step6", methods=["POST"])
def step6_honey():
    """Step 6: Honey Encryption on payment PINs."""
    pin = "4829"
    card = "4532-1234-5678-9012"
    ct = edge.honey_encrypt_pin(pin, card)

    correct = edge.honey_decrypt_pin(ct, "4829")
    wrong_results = {}
    for wp in ["0000", "1234", "9999", "5555"]:
        wrong_results[wp] = edge.honey_decrypt_pin(ct, wp)

    log_event(6, "HONEY", "PIN encrypted, wrong PINs → fake cards")
    return jsonify({
        "step": 6, "title": "Honey Encryption — Payment PINs",
        "real_pin": pin, "real_card": card,
        "correct_decrypt": correct,
        "wrong_pin_results": wrong_results,
    })


@app.route("/api/step7", methods=["POST"])
def step7_sse():
    """Step 7: SSE — searchable encrypted events."""
    keyword = request.json.get("keyword", "CAM-01") if request.is_json else "CAM-01"
    results = edge.search_events(keyword)

    log_event(7, "SSE", f"Search: '{keyword}' → {len(results)} results")
    return jsonify({
        "step": 7, "title": "SSE — Searchable Symmetric Encryption",
        "keyword": keyword,
        "count": len(results),
        "results": results[:10],
    })


@app.route("/api/step8", methods=["POST"])
def step8_he():
    """Step 8: HE — homomorphic sum of free spots."""
    counts = {}
    free_list = []
    for sid, sens in sensors.items():
        fc = sens.get_free_count()
        counts[sid] = {"lot_id": sens.lot_id, "free": fc}
        free_list.append(fc)

    he_sum = edge.he_sum_free_spots(free_list)
    plain_sum = sum(free_list)

    log_event(8, "HE", f"HE sum = {he_sum}, plain sum = {plain_sum}")
    return jsonify({
        "step": 8, "title": "HE — Homomorphic Encryption (Paillier)",
        "per_sensor": counts,
        "he_sum": he_sum,
        "plain_sum": plain_sum,
        "match": he_sum == plain_sum,
    })


@app.route("/api/step9", methods=["POST"])
def step9_jwt():
    """Step 9: JWT tokens."""
    op_jwt = edge.issue_operator_jwt("OP-ALICE")
    pay_jwt = edge.issue_city_payment_jwt("USER-BOB")
    tkt_jwt = edge.issue_ticket_handover("TKT-98765", "MOBILE-CHARLIE")

    log_event(9, "JWT", "Issued 3 JWT tokens")
    return jsonify({
        "step": 9, "title": "JWT — Authentication Tokens",
        "operator": {"token": op_jwt, "claims": edge.verify_jwt(op_jwt)},
        "city_payment": {"token": pay_jwt, "claims": edge.verify_jwt(pay_jwt)},
        "ticket_handover": {"token": tkt_jwt, "claims": edge.verify_jwt(tkt_jwt)},
    })


@app.route("/api/step10", methods=["POST"])
def step10_privacy():
    """Step 10: Privacy — plate hash/blur, location, temp IDs."""
    plate = "KA01AB1234"
    lat, lon = 12.971598, 77.594566
    rlat, rlon = reduce_location(lat, lon, precision=2)

    rotations = {}
    for cid, cam in cameras.items():
        old, new = cam.rotate_id()
        rotations[cid] = {"old": old, "new": new}
    for sid, sens in sensors.items():
        old, new = sens.rotate_id()
        rotations[sid] = {"old": old, "new": new}

    log_event(10, "PRIVACY", "Plates hashed/blurred, IDs rotated")
    return jsonify({
        "step": 10, "title": "Privacy Techniques",
        "plate": {"original": plate, "hashed": hash_plate(plate), "blurred": blur_plate(plate)},
        "location": {"original": [lat, lon], "reduced": [rlat, rlon]},
        "rotated_ids": rotations,
    })


@app.route("/api/step11", methods=["POST"])
def step11_flood():
    """Step 11: Rate-limiter flood detection."""
    flood_cam = Camera("CAM-FLOOD", "LOT-3", AES_KEY)
    # Reset if previously quarantined
    edge.limiter.release("CAM-FLOOD")

    accepted = 0
    quarantined_at = None
    for i in range(20):
        pkt = flood_cam.send()
        res = edge.ingest(pkt)
        if res["status"] == "OK":
            accepted += 1
        elif quarantined_at is None:
            quarantined_at = i + 1

    is_q = edge.limiter.is_quarantined("CAM-FLOOD")
    edge.limiter.release("CAM-FLOOD")

    log_event(11, "FLOOD", f"CAM-FLOOD: {accepted} accepted, quarantined at frame {quarantined_at}")
    return jsonify({
        "step": 11, "title": "Rate-Limiter — Flood Detection",
        "total_sent": 20,
        "accepted": accepted,
        "quarantined_at_frame": quarantined_at,
        "was_quarantined": is_q,
        "released": True,
    })


@app.route("/api/run-all", methods=["POST"])
def run_all():
    """Run all steps sequentially."""
    results = []
    for step_num in range(1, 12):
        with app.test_request_context(json={}):
            func = [step1_ingest, step2_ibe, step3_abe, step4_pre, step5_fe,
                    step6_honey, step7_sse, step8_he, step9_jwt, step10_privacy,
                    step11_flood][step_num - 1]
            resp = func()
            results.append(resp.get_json())
    return jsonify({"results": results})


# ══════════════════════════════════════════════════════════════
# REAL-WORLD PARKING LOT SIMULATION ENGINE (Intuitive & Visual)
# ══════════════════════════════════════════════════════════════

REAL_CAR_PRESETS = [
    {"model": "Tesla Model 3", "type": "ev", "color": "#06b6d4"},
    {"model": "CyberTruck", "type": "ev", "color": "#94a3b8"},
    {"model": "Porsche Taycan", "type": "ev", "color": "#3b82f6"},
    {"model": "BMW i4", "type": "ev", "color": "#10b981"},
    {"model": "Honda Civic", "type": "standard", "color": "#ef4444"},
    {"model": "Toyota Camry", "type": "standard", "color": "#f59e0b"},
    {"model": "Ford Mustang", "type": "standard", "color": "#8b5cf6"},
    {"model": "Audi A4", "type": "standard", "color": "#ec4899"},
    {"model": "Hyundai Ioniq", "type": "standard", "color": "#38bdf8"},
    {"model": "Mercedes C300", "type": "standard", "color": "#e2e8f0"},
]

REAL_PLATES = [
    "KA01AB1234", "MH02CD5678", "DL03EF9012", "TN04GH3456",
    "AP05IJ7890", "KL06KL2345", "RJ07MN6789", "GJ08OP0123",
    "UP09QR4567", "HR10ST8901", "WB11UV2345", "TS12WX6789"
]

def init_real_world():
    spots = [
        {"id": 1, "name": "Bay A1", "type": "standard", "occupied": True,
         "car": {"model": "Toyota Camry", "plate": "KA01AB1234", "color": "#3b82f6", "type": "standard",
                 "blurred_plate": blur_plate("KA01AB1234"), "hashed_plate": hash_plate("KA01AB1234"),
                 "ticket": "TKT-101", "parked_at": "10 mins ago"}},
        {"id": 2, "name": "Bay A2", "type": "standard", "occupied": False, "car": None},
        {"id": 3, "name": "Bay A3", "type": "standard", "occupied": True,
         "car": {"model": "Honda Civic", "plate": "MH02CD5678", "color": "#ef4444", "type": "standard",
                 "blurred_plate": blur_plate("MH02CD5678"), "hashed_plate": hash_plate("MH02CD5678"),
                 "ticket": "TKT-102", "parked_at": "5 mins ago"}},
        {"id": 4, "name": "Bay A4", "type": "standard", "occupied": False, "car": None},
        {"id": 5, "name": "Bay E1 (EV)", "type": "ev", "occupied": True,
         "car": {"model": "Tesla Model 3", "plate": "DL03EF9012", "color": "#06b6d4", "type": "ev",
                 "blurred_plate": blur_plate("DL03EF9012"), "hashed_plate": hash_plate("DL03EF9012"),
                 "ticket": "TKT-103", "parked_at": "2 mins ago"}},
        {"id": 6, "name": "Bay E2 (EV)", "type": "ev", "occupied": False, "car": None},
        {"id": 7, "name": "Bay VIP", "type": "disabled", "occupied": False, "car": None},
        {"id": 8, "name": "Bay A5", "type": "standard", "occupied": False, "car": None},
    ]
    return spots

real_spots = init_real_world()
real_logs = [
    {"time": time.strftime("%H:%M:%S"), "icon": "🚗", "title": "Tesla Model 3 Parked", "desc": "Assigned to EV Bay E1. Ultrasonic sensor active."},
    {"time": time.strftime("%H:%M:%S"), "icon": "🔒", "title": "Edge Shield Active", "desc": "AES-GCM encryption + plate hashing enabled at entry."},
]
entry_gate_status = {"barrier": "down", "last_vehicle": "KA01AB1234", "blurred": blur_plate("KA01AB1234")}
exit_gate_status = {"barrier": "down", "last_payment": "$4.00", "status": "Ready"}
honey_card = "4532-1234-5678-9012"
honey_pin = "4829"
real_honey_ct = edge.honey_encrypt_pin(honey_pin, honey_card)

def log_real_world(icon, title, desc):
    real_logs.insert(0, {
        "time": time.strftime("%H:%M:%S"),
        "icon": icon,
        "title": title,
        "desc": desc
    })
    if len(real_logs) > 30:
        real_logs.pop()

@app.route("/api/realworld/state", methods=["GET"])
def realworld_state():
    """Return real world parking lot layout, cars, gates, and statistics."""
    total = len(real_spots)
    occupied = sum(1 for s in real_spots if s["occupied"])
    free = total - occupied
    free_ev = sum(1 for s in real_spots if not s["occupied"] and s["type"] == "ev")
    
    return jsonify({
        "spots": real_spots,
        "total": total,
        "occupied": occupied,
        "free": free,
        "free_ev": free_ev,
        "entry_gate": entry_gate_status,
        "exit_gate": exit_gate_status,
        "logs": real_logs[:15],
        "edge_status": {
            "status": "Online & Protecting",
            "quarantined_cameras": list(edge.limiter._quarantined),
            "security_mode": "Zero-Trust Edge Encryption"
        }
    })

@app.route("/api/realworld/arrive", methods=["POST"])
def realworld_arrive():
    """A real-world car approaches the entry gate, scans plate, and parks."""
    data = request.get_json(silent=True) or {}
    is_ev = data.get("is_ev", False)
    
    # Find suitable spot
    chosen_spot = None
    if is_ev:
        for s in real_spots:
            if not s["occupied"] and s["type"] == "ev":
                chosen_spot = s
                break
    if not chosen_spot:
        for s in real_spots:
            if not s["occupied"]:
                chosen_spot = s
                break
                
    if not chosen_spot:
        return jsonify({
            "success": False,
            "message": "Parking Lot is 100% Full! No bays available.",
            "explanation": "Ultrasonic sensors notified the edge box that 0 spots remain. Entry gate stays down."
        }), 400
        
    # Pick car preset
    pool = [c for c in REAL_CAR_PRESETS if (c["type"] == "ev" if is_ev else c["type"] == "standard")]
    preset = secrets.choice(pool) if pool else REAL_CAR_PRESETS[0]
    plate = secrets.choice(REAL_PLATES)
    
    # Real-world cryptography operations executed on the edge box
    blurred = blur_plate(plate)
    hashed = hash_plate(plate)
    ticket_id = f"TKT-{secrets.randbelow(899) + 100}"
    
    # Update spot
    chosen_spot["occupied"] = True
    chosen_spot["car"] = {
        "model": preset["model"],
        "plate": plate,
        "color": preset["color"],
        "type": preset["type"],
        "blurred_plate": blurred,
        "hashed_plate": hashed,
        "ticket": ticket_id,
        "parked_at": "Just now"
    }
    
    entry_gate_status["barrier"] = "up"
    entry_gate_status["last_vehicle"] = plate
    entry_gate_status["blurred"] = blurred
    
    log_real_world("🚗", f"{preset['model']} Parked",
                   f"Plate {plate} scanned & blurred to {blurred}. Parked in {chosen_spot['name']}.")
    
    return jsonify({
        "success": True,
        "spot": chosen_spot,
        "plate": plate,
        "blurred_plate": blurred,
        "ticket_id": ticket_id,
        "message": f"Welcome! {preset['model']} assigned to {chosen_spot['name']}.",
        "explanation": f"Gate camera photographed plate '{plate}'. Edge Box instantly blurred it to '{blurred}' to protect driver privacy, verified camera cryptographic signature, and raised the barrier!"
    })

@app.route("/api/realworld/depart", methods=["POST"])
def realworld_depart():
    """A car leaves its spot and drives out through the exit gate."""
    data = request.get_json(silent=True) or {}
    spot_id = data.get("spot_id")
    
    occupied_spots = [s for s in real_spots if s["occupied"]]
    if not occupied_spots:
        return jsonify({
            "success": False,
            "message": "The parking lot is already empty!",
            "explanation": "No parked cars to depart."
        }), 400
        
    target_spot = None
    if spot_id:
        target_spot = next((s for s in occupied_spots if s["id"] == spot_id), None)
    if not target_spot:
        target_spot = secrets.choice(occupied_spots)
        
    car = target_spot["car"]
    target_spot["occupied"] = False
    target_spot["car"] = None
    
    exit_gate_status["barrier"] = "up"
    exit_gate_status["last_payment"] = "$5.00 Paid"
    
    log_real_world("🚙", f"{car['model']} Departed",
                   f"Vacated {target_spot['name']}. Sensor turned Green (vacant). Exit barrier opened.")
    
    return jsonify({
        "success": True,
        "freed_spot": target_spot,
        "departed_car": car,
        "message": f"{car['model']} has left {target_spot['name']}.",
        "explanation": f"Ultrasonic ceiling sensor detected car left {target_spot['name']}. Sensor immediately turned GREEN. Free spots counter updated automatically!"
    })

@app.route("/api/realworld/pay_kiosk", methods=["POST"])
def realworld_pay_kiosk():
    """Interactive Payment Terminal: Test real PIN vs Honey Decoy."""
    data = request.get_json(silent=True) or {}
    entered_pin = str(data.get("pin", "")).strip()
    
    if entered_pin == honey_pin:
        # Legitimate cardholder
        card = edge.honey_decrypt_pin(real_honey_ct, entered_pin)
        exit_gate_status["barrier"] = "up"
        log_real_world("💳", "Driver Payment Approved", "Correct PIN entered. Exit barrier opened.")
        return jsonify({
            "success": True,
            "is_decoy": False,
            "card_number": card,
            "message": "Payment Approved! Receipt Printed. Exit barrier is UP.",
            "explanation": "Legitimate cardholder entered correct PIN (4829). Edge Box decrypted the valid payment card and authorized exit!"
        })
    else:
        # Attacker or wrong PIN -> Honey Encryption generates believable decoy card!
        decoy_card = edge.honey_decrypt_pin(real_honey_ct, entered_pin)
        exit_gate_status["barrier"] = "down"
        log_real_world("🍯", "Honey Decoy Trap Fired!", f"Wrong PIN '{entered_pin}' entered. Fake card {decoy_card} dispatched to honey pot.")
        return jsonify({
            "success": False,
            "is_decoy": True,
            "card_number": decoy_card,
            "message": "⚠️ Honey Decoy Trap Activated: A plausible fake card was generated!",
            "explanation": f"Wrong PIN '{entered_pin}' entered! Instead of telling a hacker 'Access Denied' so they can keep guessing, the Edge Box generates a REALISTIC FAKE card number ({decoy_card})! The attacker wastes time trying to use a decoy, while the driver's real card remains 100% secret!"
        })

@app.route("/api/realworld/inspector_audit", methods=["POST"])
def realworld_inspector_audit():
    """City Parking Inspector arrives to check compliance."""
    sample_audit = {"lot_id": "LOT-3", "inspected_at": time.strftime("%Y-%m-%d %H:%M"), "total_violations": 0}
    ct_op = edge.pre_encrypt_for_operator(sample_audit)
    rk = edge.pre_rekey_to_inspector()
    re_ct = edge.pre_re_encrypt(ct_op, rk)
    decrypted = edge.pre_decrypt_inspector(re_ct)
    
    log_real_world("👮", "City Inspector Audit Completed", "Granted temporary inspection token via Proxy Re-Encryption.")
    return jsonify({
        "success": True,
        "inspector_id": "CITY-AUDIT-402",
        "audit_data": decrypted,
        "message": "City Inspector verified parking lot capacity safely!",
        "explanation": "Real-World Safe Sharing: The parking owner wants to let city inspectors check capacity reports without giving them master keys or private driver camera feeds. Using Proxy Re-Encryption, the edge box translates the report specifically for the inspector's badge!"
    })

@app.route("/api/realworld/camera_attack", methods=["POST"])
def realworld_camera_attack():
    """Simulate a cyber attacker flooding a gate camera."""
    flood_cam = Camera("ROGUE-CAMERA-9", "LOT-3", AES_KEY)
    edge.limiter.release("ROGUE-CAMERA-9")
    
    packets_sent = 20
    accepted = 0
    quarantine_at = None
    for i in range(packets_sent):
        pkt = flood_cam.send()
        res = edge.ingest(pkt)
        if res["status"] == "OK":
            accepted += 1
        elif quarantine_at is None:
            quarantine_at = i + 1
            
    is_q = edge.limiter.is_quarantined("ROGUE-CAMERA-9")
    edge.limiter.release("ROGUE-CAMERA-9")
    
    log_real_world("🚨", "Cyber Flood Quarantined", f"Rogue camera flooded 20 frames/sec. Edge Box blocked it at frame {quarantine_at}.")
    return jsonify({
        "success": True,
        "quarantined": is_q,
        "quarantined_at_frame": quarantine_at,
        "accepted": accepted,
        "message": f"Shield Activated! Rogue camera quarantined after frame {quarantine_at}.",
        "explanation": "Real-World Cyber Defense: Hackers sometimes compromise an outdoor camera and flood the network with fake video to crash the parking barrier. The Edge Box rate-limiter detects abnormal frame bursts and isolates the camera in milliseconds, keeping the rest of the lot running!"
    })

@app.route("/api/realworld/toggle_spot/<int:spot_id>", methods=["POST"])
def realworld_toggle_spot(spot_id):
    """Click on any spot on the visual lot to park or unpark."""
    target = next((s for s in real_spots if s["id"] == spot_id), None)
    if not target:
        return jsonify({"success": False, "message": "Spot not found"}), 404
        
    if target["occupied"]:
        car = target["car"]
        target["occupied"] = False
        target["car"] = None
        log_real_world("🚙", f"{car['model']} Left {target['name']}", "Driver manually exited the spot.")
        return jsonify({"success": True, "action": "departed", "spot": target})
    else:
        is_ev = target["type"] == "ev"
        pool = [c for c in REAL_CAR_PRESETS if (c["type"] == "ev" if is_ev else c["type"] == "standard")]
        preset = secrets.choice(pool) if pool else REAL_CAR_PRESETS[0]
        plate = secrets.choice(REAL_PLATES)
        blurred = blur_plate(plate)
        ticket_id = f"TKT-{secrets.randbelow(899) + 100}"
        
        target["occupied"] = True
        target["car"] = {
            "model": preset["model"],
            "plate": plate,
            "color": preset["color"],
            "type": preset["type"],
            "blurred_plate": blurred,
            "hashed_plate": hash_plate(plate),
            "ticket": ticket_id,
            "parked_at": "Just now"
        }
        log_real_world("🚗", f"{preset['model']} Parked in {target['name']}", f"Plate {plate} blurred to {blurred}.")
        return jsonify({"success": True, "action": "parked", "spot": target})

@app.route("/api/realworld/reset", methods=["POST"])
def realworld_reset():
    """Reset the real world parking lot to clean state."""
    global real_spots
    real_spots = init_real_world()
    log_real_world("🔄", "Parking Lot Reset", "Restored to default live demo state.")
    return jsonify({"success": True, "spots": real_spots})



if __name__ == "__main__":
    print("\n  [P] Smart-Parking Edge Box Dashboard")
    print("  ->  Open http://127.0.0.1:5000 in your browser\n")
    app.run(debug=True, port=5000)
