"""
Generates synthetic digital-signature-event feature data for training
and demoing the anomaly detector, since a real PKI/blockchain traffic
dump usually isn't available for a hackathon prototype.

Features per event (all normalized to roughly [0,1] before use):
  1. signing_rate      - signatures/minute from this signer
  2. verify_fail_ratio - fraction of recent verifications that failed
  3. key_reuse_score   - how often the same key material appears across signers
  4. time_of_day       - normalized hour (captures off-hours signing bursts)
  5. key_age_days      - normalized age of the signing key

Normal traffic clusters tightly; injected attacks (replay bursts, key
reuse/theft, forged-signature floods) are pushed to the edges of the
feature space.
"""
import numpy as np


def generate_dataset(n_normal: int = 300, n_anomalous: int = 60, seed: int = 42):
    rng = np.random.default_rng(seed)

    # --- Normal behaviour: tight cluster ---
    normal = rng.normal(loc=[0.2, 0.02, 0.05, 0.5, 0.4],
                         scale=[0.08, 0.02, 0.03, 0.2, 0.2],
                         size=(n_normal, 5))

    # --- Anomalies: three attack patterns mixed together ---
    n_each = n_anomalous // 3

    # 1) Replay-attack burst: high signing rate, high verify-fail ratio
    replay = rng.normal(loc=[0.9, 0.6, 0.1, 0.5, 0.4],
                         scale=[0.05, 0.15, 0.05, 0.2, 0.2],
                         size=(n_each, 5))

    # 2) Key-theft / reuse: same key material reused across many signers
    key_theft = rng.normal(loc=[0.3, 0.1, 0.85, 0.5, 0.9],
                            scale=[0.1, 0.05, 0.1, 0.2, 0.05],
                            size=(n_each, 5))

    # 3) Off-hours forged-signature flood
    off_hours = rng.normal(loc=[0.85, 0.4, 0.2, 0.05, 0.4],
                            scale=[0.08, 0.1, 0.1, 0.05, 0.2],
                            size=(n_anomalous - 2 * n_each, 5))

    anomalous = np.vstack([replay, key_theft, off_hours])

    X = np.clip(np.vstack([normal, anomalous]), 0, 1)
    y = np.concatenate([np.zeros(len(normal)), np.ones(len(anomalous))])

    # Shuffle
    idx = rng.permutation(len(X))
    return X[idx], y[idx]


FEATURE_NAMES = [
    "signing_rate", "verify_fail_ratio", "key_reuse_score",
    "time_of_day", "key_age_days",
]
