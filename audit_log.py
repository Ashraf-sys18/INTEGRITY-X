"""
Hash-Chained Audit Log
------------------------
A lightweight blockchain-style tamper-evident log: every detection
record includes the hash of the previous record, so any retroactive
edit breaks the chain and is immediately detectable. This reuses the
same chaining principle as the log-integrity project, applied here to
signature-threat detection events.
"""
import hashlib
import json
import time
from typing import List
from models import AuditRecord

GENESIS_HASH = "0" * 64


def _compute_hash(index: int, timestamp: float, event_id: str,
                   signer_id: str, risk_level: str,
                   anomaly_score: float, prev_hash: str) -> str:
    payload = json.dumps({
        "index": index,
        "timestamp": timestamp,
        "event_id": event_id,
        "signer_id": signer_id,
        "risk_level": risk_level,
        "anomaly_score": anomaly_score,
        "prev_hash": prev_hash,
    }, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


class AuditChain:
    def __init__(self):
        self.chain: List[AuditRecord] = []

    def append(self, event_id: str, signer_id: str, risk_level: str,
               anomaly_score: float) -> AuditRecord:
        index = len(self.chain)
        prev_hash = self.chain[-1].hash if self.chain else GENESIS_HASH
        timestamp = time.time()
        h = _compute_hash(index, timestamp, event_id, signer_id,
                           risk_level, anomaly_score, prev_hash)
        record = AuditRecord(
            index=index, timestamp=timestamp, event_id=event_id,
            signer_id=signer_id, risk_level=risk_level,
            anomaly_score=anomaly_score, prev_hash=prev_hash, hash=h,
        )
        self.chain.append(record)
        return record

    def verify_integrity(self) -> bool:
        """Recomputes every hash in order; returns False if anything
        in the chain has been tampered with."""
        prev_hash = GENESIS_HASH
        for record in self.chain:
            expected = _compute_hash(
                record.index, record.timestamp, record.event_id,
                record.signer_id, record.risk_level,
                record.anomaly_score, prev_hash,
            )
            if expected != record.hash or record.prev_hash != prev_hash:
                return False
            prev_hash = record.hash
        return True

    def to_list(self):
        return [r.model_dump() for r in self.chain]
