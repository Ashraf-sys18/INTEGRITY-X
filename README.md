#Quantum-Inspired Cyber Threat Detection for Digital Signature Security

A worototype for SIH 2026 problem statement (Blockchain &
Cybersecurity track). It detects two kinds of threats to digital signature
security at once:

1. **Post-quantum vulnerability** — signatures using algorithms (RSA, ECDSA,
   DSA) that will be broken by Shor's algorithm once large-scale quantum
   computers exist ("harvest now, decrypt later" risk), with migration
   recommendations to NIST-selected post-quantum algorithms (Dilithium,
   Falcon, SPHINCS+, Kyber).
2. **Anomalous signing behaviour** — replay bursts, key reuse/theft, and
   off-hours forged-signature floods — using a **quantum-inspired anomaly
   detector**: signature-event features are embedded into a simulated
   4-qubit quantum circuit (PennyLane, `default.qubit` device), and the
   resulting quantum-kernel similarity feeds a classical SVM. No real
   quantum hardware is required.

Every detection is written to a **SHA-256 hash-chained audit log**
(blockchain-style tamper evidence): retroactively editing any record breaks
the chain, which `/audit/verify` detects immediately.

## Project structure

```
├── backend/
│   ├── main.py              FastAPI app — all API endpoints
│   ├── models.py            Pydantic data models
│   ├── pqc_risk.py          Rule-based post-quantum risk scoring
│   ├── quantum_detector.py  PennyLane quantum-kernel + SVM anomaly detector
│   ├── synthetic_data.py    Synthetic training/demo data generator
│   ├── audit_log.py         Hash-chained tamper-evident audit log
│   └── requirements.txt
└── frontend/
    └── index.html           Live dashboard (charts, event table, audit status)
```

## Running it

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Then open `frontend/index.html` directly in a browser (no build step —
it's plain HTML/JS + Chart.js from a CDN). It talks to `http://127.0.0.1:8000`.

Click **"Simulate Normal Traffic"** and **"Simulate Attack Burst"** to feed
the pipeline synthetic events and watch risk scores, anomaly flags, and the
audit chain update live.

## API endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/ingest` | POST | Submit one real signature event for scoring |
| `/simulate?n=10&attack=false` | POST | Generate synthetic events (demo) |
| `/events?limit=50` | GET | Recent scored events |
| `/stats` | GET | Aggregate counts, risk breakdown |
| `/audit` | GET | Full audit chain |
| `/audit/verify` | GET | Recomputes all hashes — detects tampering |

## Why this is "quantum-inspired" and not just a buzzword

The anomaly detector genuinely uses a quantum feature map: each event's
5 behavioural features (signing rate, verification-failure ratio, key-reuse
score, time-of-day, key age) are angle-embedded onto qubits, entangled with
CNOTs, and the resulting statevectors' pairwise overlaps form a quantum
kernel matrix — the same technique used in real quantum machine learning
research (quantum kernel SVMs), just run on a classical simulator so it
works on ordinary hardware today while remaining forward-compatible with
real quantum backends later.

## Extending for the SIH final round

- Swap `synthetic_data.py` for real signature logs (TLS handshake logs,
  blockchain transaction signatures, code-signing certs)
- Persist the audit chain to disk or an actual append-only store
- Add a `/retrain` endpoint so the detector can be updated with labeled
  incident data over time
- Try a larger qubit count or an alternate embedding (amplitude embedding)
  for the quantum kernel to compare accuracy

