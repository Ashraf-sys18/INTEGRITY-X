"""
SIH26141 - Quantum-Inspired Cyber Threat Detection for Digital
Signature Security
==================================================================
FastAPI backend tying together:
  1. Signature event ingestion
  2. PQC (post-quantum-cryptography) risk scoring        -> pqc_risk.py
  3. Quantum-inspired anomaly detection (PennyLane+SVM)   -> quantum_detector.py
  4. Hash-chained tamper-evident audit log                -> audit_log.py

Run with:  uvicorn main:app --reload --port 8000
Then open frontend/index.html in a browser (it calls localhost:8000).
"""
import random
import time
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import numpy as np

from models import SignatureEvent, RiskAssessment, AnomalyResult
from pqc_risk import assess_risk
from quantum_detector import QuantumInspiredDetector
from synthetic_data import generate_dataset, FEATURE_NAMES
from audit_log import AuditChain

app = FastAPI(title="SIH26141 - Quantum-Inspired Signature Threat Detection")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- Global (in-memory) state for the prototype ----
detector = QuantumInspiredDetector()
audit = AuditChain()
events_log = []          # list of dicts: event + risk + anomaly

ALGOS = ["RSA-1024", "RSA-2048", "RSA-4096", "ECDSA-P256",
         "ECDSA-P384", "Ed25519", "Dilithium2", "DSA-1024"]


def _bootstrap_train():
    """Train the quantum-inspired detector once at startup on synthetic
    data so the API is immediately usable for a demo."""
    X, y = generate_dataset(n_normal=60, n_anomalous=24)  # kept small: full
    detector.fit(X, y)                                     # statevector sim


_bootstrap_train()


@app.get("/")
def root():
    return {
        "project": "SIH26141 - Quantum-Inspired Cyber Threat Detection for Digital Signature Security",
        "status": "running",
        "endpoints": ["/ingest", "/simulate", "/events", "/audit", "/audit/verify", "/stats"],
    }


def _features_from_event(ev: SignatureEvent, recent_events) -> list:
    """Derive the 5 behavioural features the detector expects from a raw
    signature event plus recent history for that signer."""
    same_signer = [e for e in recent_events if e["event"]["signer_id"] == ev.signer_id]
    window = same_signer[-20:]

    signing_rate = min(len(window) / 20.0, 1.0)
    fails = [e for e in window if e["event"]["verification_result"] == "invalid"]
    verify_fail_ratio = (len(fails) / len(window)) if window else 0.0

    key_users = set(e["event"]["signer_id"] for e in recent_events[-50:]
                     if e["event"]["algorithm"] == ev.algorithm)
    key_reuse_score = min(len(key_users) / 10.0, 1.0)

    hour = time.localtime(ev.timestamp).tm_hour
    time_of_day = hour / 24.0

    key_age_days = min((abs(hash(ev.signer_id)) % 400) / 400.0, 1.0)

    return [signing_rate, verify_fail_ratio, key_reuse_score, time_of_day, key_age_days]


@app.post("/ingest")
def ingest(event: SignatureEvent):
    risk = assess_risk(event)
    features = _features_from_event(event, events_log)
    pred, prob = detector.predict(np.array([features]))
    anomaly = AnomalyResult(
        event_id=event.event_id,
        is_anomalous=bool(pred[0]),
        anomaly_score=float(prob[0]),
        model_confidence=float(max(prob[0], 1 - prob[0])),
        notes="Quantum-kernel SVM flagged this signing pattern as anomalous."
              if pred[0] else "Signing pattern consistent with normal behaviour.",
    )
    record = audit.append(event.event_id, event.signer_id, risk.risk_level, anomaly.anomaly_score)

    entry = {"event": event.model_dump(), "risk": risk.model_dump(),
              "anomaly": anomaly.model_dump(), "audit_index": record.index}
    events_log.append(entry)
    return entry


@app.post("/simulate")
def simulate(n: int = 15, attack: bool = False):
    """Generate n synthetic signature events (optionally attack-flavoured)
    and run them through the full pipeline, for demoing without a real
    data source connected."""
    results = []
    for _ in range(n):
        if attack and random.random() < 0.6:
            algo = random.choice(["RSA-1024", "DSA-1024", "RSA-2048"])
            burst_signer = "signer_ATTACK"
            ev = SignatureEvent(
                signer_id=burst_signer,
                algorithm=algo,
                key_size_bits=int(algo.split("-")[-1]) if algo.split("-")[-1].isdigit() else 1024,
                timestamp=time.time(),
                verification_result=random.choice(["valid", "invalid", "invalid"]),
                context="simulated_attack",
            )
        else:
            algo = random.choice(ALGOS)
            ev = SignatureEvent(
                signer_id=f"signer_{random.randint(1, 8)}",
                algorithm=algo,
                key_size_bits=int(algo.split("-")[-1]) if algo.split("-")[-1].isdigit() else 256,
                timestamp=time.time(),
                verification_result="valid",
                context="simulated_normal",
            )
        results.append(ingest(ev))
    return results


@app.get("/events")
def get_events(limit: int = 50):
    return events_log[-limit:]


@app.get("/audit")
def get_audit():
    return audit.to_list()


@app.get("/audit/verify")
def verify_audit():
    return {"chain_intact": audit.verify_integrity(), "length": len(audit.chain)}


@app.get("/stats")
def stats():
    if not events_log:
        return {"total": 0}
    total = len(events_log)
    anomalous = sum(1 for e in events_log if e["anomaly"]["is_anomalous"])
    quantum_vulnerable = sum(1 for e in events_log if e["risk"]["quantum_vulnerable"])
    by_risk = {}
    for e in events_log:
        lvl = e["risk"]["risk_level"]
        by_risk[lvl] = by_risk.get(lvl, 0) + 1
    return {
        "total": total,
        "anomalous": anomalous,
        "quantum_vulnerable": quantum_vulnerable,
        "risk_breakdown": by_risk,
        "audit_chain_intact": audit.verify_integrity(),
    }


app.mount("/static", StaticFiles(directory="../frontend", html=True), name="static")
