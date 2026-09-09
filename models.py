"""
Data models for SIH26141 - Quantum-Inspired Cyber Threat Detection
for Digital Signature Security
"""
from pydantic import BaseModel, Field
from typing import Optional, Literal
from datetime import datetime
import uuid


class SignatureEvent(BaseModel):
    """A single digital signature creation/verification event ingested
    from a PKI, blockchain node, TLS handshake log, or similar source."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    signer_id: str
    algorithm: str          # e.g. "RSA-2048", "ECDSA-P256", "Ed25519", "Dilithium2"
    key_size_bits: int
    timestamp: float        # unix epoch seconds
    verification_result: Literal["valid", "invalid"]
    source_ip: Optional[str] = None
    context: Optional[str] = None  # e.g. "tls_handshake", "blockchain_tx", "code_signing"


class RiskAssessment(BaseModel):
    event_id: str
    quantum_vulnerable: bool
    risk_level: Literal["low", "medium", "high", "critical"]
    risk_score: float          # 0-100
    reason: str
    recommended_algorithm: Optional[str] = None


class AnomalyResult(BaseModel):
    event_id: str
    is_anomalous: bool
    anomaly_score: float       # 0-1, higher = more anomalous
    model_confidence: float
    notes: str


class AuditRecord(BaseModel):
    index: int
    timestamp: float
    event_id: str
    signer_id: str
    risk_level: str
    anomaly_score: float
    prev_hash: str
    hash: str
