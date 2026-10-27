# 🅿️ Smart-Parking Edge Box Simulation

An interactive, visual real-world simulation and edge computing security dashboard for smart parking lots. Demonstrates zero-trust cryptography, privacy protections, and cyber defense on the edge.

---

## 🌟 Key Features

### 🏢 Real-World Interactive Parking Simulator
- **Live Visual 8-Bay Parking Facility**: Visual asphalt layout, overhead ultrasonic sensors with glowing LEDs (🟢 Green = Vacant, 🔴 Red = Occupied, ⚡ Cyan = EV Charging), and top-down car graphics.
- **Automated Boom Barriers**: Animated entry and exit gates that open when verified by the Edge Box.
- **Entry Camera & Privacy Shield**: Live plate scanning with SHA-256 hashing and visual blurring before data is stored.
- **Interactive Payment Kiosk**: Physical ATM-style terminal with 4-digit PIN pad.
- **Honey Encryption Decoy Trap**: Entering an incorrect PIN generates realistic synthetic credit card numbers to entrap intruders while keeping real driver credentials completely safe!
- **DDoS Cyber Defense**: Token-bucket rate limiter that isolates flooding cameras in milliseconds.
- **Guided Story Mode**: 1-click automated tour walking through a day in the life of the parking facility.

---

## 🔬 11 Cryptographic Mechanisms Implemented

1. **AES-256-GCM + ECC Digital Signatures**: Secure camera and sensor data ingestion with tamper verification.
2. **Identity-Based Encryption (IBE)**: Direct encryption to parking lot identity (`LOT-3`) without certificate exchange.
3. **Attribute-Based Encryption (ABE)**: Fine-grained access control policy (`ParkingAttendant AND Lot3`).
4. **Proxy Re-Encryption (PRE)**: Grants temporary inspection credentials to City Parking Inspectors without disclosing master keys.
5. **Functional Encryption (FE)**: Computes EV grid charging demand and occupancy percentages without decrypting individual vehicle records.
6. **Honey Encryption**: Protects payment terminal PINs by returning plausible dummy credit card numbers on wrong guesses.
7. **Searchable Symmetric Encryption (SSE)**: Enables operators to search encrypted event records via cryptographic trapdoors.
8. **Paillier Homomorphic Encryption (HE)**: Aggregates free parking spots across multiple edge boxes without decrypting counts.
9. **JWT Multi-Role Authentication**: Operator tokens, city payment tokens, and ticket handover tokens.
10. **Driver Privacy Protections**: License plate hashing/blurring, GPS coordinate truncation, and rotating device IDs.
11. **Token-Bucket Rate Limiter**: Quarantines rogue or compromised camera hardware during frame flooding attacks.

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Interactive Web Application
```bash
python app.py
```
Open **[http://127.0.0.1:5000](http://127.0.0.1:5000)** in your browser.

### 3. Run Command-Line Terminal Demo
```bash
python demo.py
```

---

## 📁 Repository Structure
```
├── app.py              # Flask server & Real-World Simulation REST API
├── camera.py           # Simulated camera process (AES + HMAC + IBE + Privacy)
├── sensor.py           # Simulated IoT bay sensor process (AES + ECC)
├── parking_edge.py     # Parking Edge Box Server implementation
├── crypto_utils.py     # Core cryptographic implementations (IBE, ABE, PRE, FE, HE, Honey)
├── demo.py             # Complete CLI test harness for all 11 specifications
├── templates/
│   └── index.html      # Interactive visual simulation dashboard & crypto inspector
└── requirements.txt    # Python dependencies (pycryptodome, phe, etc.)
```
