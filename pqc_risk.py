"""
PQC Risk Engine
----------------
Scores each digital signature event for how vulnerable it is to a
"harvest-now, decrypt-later" quantum attack, based on the algorithm
and key size, and recommends a post-quantum-safe replacement.
"""
from models import SignatureEvent, RiskAssessment

# Algorithms broken outright by Shor's algorithm once a large enough
# quantum computer exists, regardless of key size.
SHOR_BREAKABLE = {"RSA", "ECDSA", "DSA", "ECDH", "DH"}

# NIST-selected post-quantum signature schemes we recommend migrating to.
PQC_RECOMMENDATIONS = {
    "RSA": "CRYSTALS-Dilithium (or Falcon for smaller signatures)",
    "ECDSA": "CRYSTALS-Dilithium (or SPHINCS+ for stateless hash-based security)",
    "DSA": "CRYSTALS-Dilithium",
    "ECDH": "CRYSTALS-Kyber (key exchange)",
    "DH": "CRYSTALS-Kyber (key exchange)",
}

# Algorithm-family prefixes already considered quantum-resistant.
PQC_SAFE_PREFIXES = ("DILITHIUM", "FALCON", "SPHINCS", "KYBER")


def _algo_family(algorithm: str) -> str:
    """Extract the algorithm family, e.g. 'RSA-2048' -> 'RSA'."""
    return algorithm.split("-")[0].upper()


def _is_pqc_safe(family: str) -> bool:
    return any(family.startswith(p) for p in PQC_SAFE_PREFIXES)


# EC-based schemes (ECDSA/ECDH) use much smaller key sizes than RSA/DSA
# for equivalent *classical* security (a 256-bit curve ~ 3072-bit RSA),
# so they need their own thresholds rather than sharing RSA's.
EC_FAMILIES = {"ECDSA", "ECDH"}


def assess_risk(event: SignatureEvent) -> RiskAssessment:
    family = _algo_family(event.algorithm)

    if _is_pqc_safe(family):
        return RiskAssessment(
            event_id=event.event_id,
            quantum_vulnerable=False,
            risk_level="low",
            risk_score=5.0,
            reason=f"{event.algorithm} is a post-quantum-resistant scheme.",
            recommended_algorithm=None,
        )

    if family in SHOR_BREAKABLE:
        # All Shor-breakable schemes are equally broken once a
        # cryptographically-relevant quantum computer exists, regardless
        # of classical key size -- but larger classical keys buy more
        # time before that happens, so we still weight risk by size,
        # using family-appropriate thresholds.
        if family in EC_FAMILIES:
            if event.key_size_bits < 256:
                risk_score, level = 90.0, "critical"
            elif event.key_size_bits < 384:
                risk_score, level = 70.0, "high"
            else:
                risk_score, level = 60.0, "high"
        else:
            if event.key_size_bits < 2048:
                risk_score, level = 95.0, "critical"
            elif event.key_size_bits < 3072:
                risk_score, level = 75.0, "high"
            else:
                risk_score, level = 55.0, "medium"

        return RiskAssessment(
            event_id=event.event_id,
            quantum_vulnerable=True,
            risk_level=level,
            risk_score=risk_score,
            reason=(
                f"{event.algorithm} relies on integer factorization / discrete "
                f"log, breakable in polynomial time by Shor's algorithm. Data "
                f"signed now can be harvested and forged retroactively once "
                f"cryptographically-relevant quantum computers exist."
            ),
            recommended_algorithm=PQC_RECOMMENDATIONS.get(family),
        )

    # Unknown / symmetric-style or already modern EdDSA (Grover gives only
    # quadratic speed-up here, considered lower relative priority).
    return RiskAssessment(
        event_id=event.event_id,
        quantum_vulnerable=False,
        risk_level="low",
        risk_score=15.0,
        reason=f"{event.algorithm} is not known to be broken by Shor's algorithm.",
        recommended_algorithm=None,
    )
