"""
ForensicChain v2.4.1 — Isolation Forest Training Pipeline
Generates realistic baseline normal activity and controlled simulated anomalies
to train and serialize the unsupervised Isolation Forest detector.
"""

import os
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

MODEL_DIR = os.path.join(os.path.dirname(__file__), "model")
MODEL_FILE = os.path.join(MODEL_DIR, "isolation_forest.joblib")
MODEL_VERSION = "v1.0-isolation-forest"


def generate_synthetic_training_dataset(n_normal=800, n_anomalies=100, random_state=42):
    """
    Synthesizes a realistic distribution of 12-feature evidence activity vectors.
    """
    rng = np.random.RandomState(random_state)

    # ── Normal Behavioral Patterns (n_normal) ──
    # [0] access_count: 1 to 12
    normal_access = rng.poisson(lam=4, size=n_normal) + 1
    # [1] failed_attempt_count: 0 (occasionally 1 typo)
    normal_failed = rng.choice([0, 0, 0, 0, 1], size=n_normal)
    # [2] transfer_count: 1 to 4 transfers in typical chain
    normal_transfers = rng.choice([1, 2, 3, 4], p=[0.4, 0.35, 0.2, 0.05], size=n_normal)
    # [3] verification_failure_count: 0 in legitimate evidence
    normal_verif_failures = np.zeros(n_normal)
    # [4] unique_actor_count: 2 to 5 distinct personnel
    normal_actors = rng.choice([2, 3, 4, 5], p=[0.2, 0.4, 0.3, 0.1], size=n_normal)
    # [5] unique_role_count: 2 to 4 roles
    normal_roles = rng.choice([2, 3, 4], p=[0.3, 0.5, 0.2], size=n_normal)
    # [6] action_frequency: 1 to 8 actions / day
    normal_freq = rng.gamma(shape=3.0, scale=1.5, size=n_normal)
    # [7] min_time_between_actions: 300 to 14400 seconds (minutes to hours between human steps)
    normal_min_time = rng.uniform(180.0, 14400.0, size=n_normal)
    # [8] unusual_hour_ratio: 0.0 to 0.10 (predominantly business hours)
    normal_unusual_hour = rng.beta(a=0.5, b=5.0, size=n_normal) * 0.15
    # [9] repeated_action_burst: 1 to 2
    normal_repeated_burst = rng.choice([1, 1, 1, 2], size=n_normal)
    # [10] unexpected_role_action: 0
    normal_unexpected_role = np.zeros(n_normal)
    # [11] custody_sequence_irregularity: 0
    normal_seq_irregularity = np.zeros(n_normal)

    X_normal = np.column_stack([
        normal_access,
        normal_failed,
        normal_transfers,
        normal_verif_failures,
        normal_actors,
        normal_roles,
        normal_freq,
        normal_min_time,
        normal_unusual_hour,
        normal_repeated_burst,
        normal_unexpected_role,
        normal_seq_irregularity
    ])

    # ── Simulated Anomalous Patterns (n_anomalies) ──
    anomalies = []

    # Scenario A: Rapid Automated Burst Attack (high action freq, sub-second intervals)
    for _ in range(n_anomalies // 5):
        anomalies.append([
            rng.randint(25, 80),            # high access
            rng.randint(2, 8),              # failed attempts
            rng.randint(5, 12),             # many transfers
            0,                              # no verif failure
            rng.randint(1, 3),              # few actors
            rng.randint(1, 2),              # single role
            rng.uniform(60.0, 250.0),       # extreme frequency
            rng.uniform(0.1, 2.5),          # sub-second min time!
            rng.uniform(0.1, 0.4),
            rng.randint(5, 12),             # large repeated burst
            0,
            0
        ])

    # Scenario B: Verification Failure / Tamper Attempt
    for _ in range(n_anomalies // 5):
        anomalies.append([
            rng.randint(3, 10),
            rng.randint(1, 5),
            rng.randint(2, 4),
            rng.randint(2, 6),              # multiple cryptographic verif failures!
            rng.randint(2, 4),
            rng.randint(2, 3),
            rng.uniform(5.0, 20.0),
            rng.uniform(60.0, 1800.0),
            rng.uniform(0.0, 0.2),
            1,
            0,
            0
        ])

    # Scenario C: Off-Hours Nocturnal Exfiltration (midnight actions)
    for _ in range(n_anomalies // 5):
        anomalies.append([
            rng.randint(15, 40),
            rng.randint(2, 6),
            rng.randint(3, 7),
            0,
            1,                              # rogue lone actor
            1,
            rng.uniform(20.0, 60.0),
            rng.uniform(30.0, 300.0),
            rng.uniform(0.75, 1.0),         # > 75% at night (23:00-05:00)!
            rng.randint(3, 6),
            1,
            0
        ])

    # Scenario D: Custody Sequence Irregularity (out of order, analysis before collection)
    for _ in range(n_anomalies // 5):
        anomalies.append([
            rng.randint(2, 8),
            0,
            rng.randint(1, 4),
            0,
            rng.randint(2, 4),
            rng.randint(2, 3),
            rng.uniform(2.0, 10.0),
            rng.uniform(300.0, 3600.0),
            rng.uniform(0.0, 0.15),
            1,
            rng.randint(1, 3),              # unexpected role
            rng.randint(2, 4)               # severe sequence irregularity!
        ])

    # Scenario E: High Unauthorized Permission Probing
    for _ in range(n_anomalies - len(anomalies)):
        anomalies.append([
            rng.randint(30, 90),            # excessive read requests
            rng.randint(8, 25),             # huge failed attempts
            1,
            0,
            rng.randint(1, 2),
            1,
            rng.uniform(40.0, 120.0),
            rng.uniform(5.0, 60.0),
            rng.uniform(0.2, 0.6),
            rng.randint(4, 9),
            0,
            0
        ])

    X_anom = np.array(anomalies, dtype=float)
    X = np.vstack([X_normal, X_anom])
    y = np.concatenate([np.ones(n_normal), -np.ones(len(anomalies))])

    return X, y


def train_isolation_forest():
    """Trains Isolation Forest and serializes model to ml/model/isolation_forest.joblib."""
    print("[ML Train] Generating synthetic baseline training distribution...")
    X_train, _ = generate_synthetic_training_dataset(n_normal=900, n_anomalies=100)

    print(f"[ML Train] Fitting IsolationForest on {X_train.shape[0]} training samples across 12 features...")
    model = IsolationForest(
        n_estimators=120,
        max_samples="auto",
        contamination=0.10,
        random_state=42,
        bootstrap=False
    )
    model.fit(X_train)

    os.makedirs(MODEL_DIR, exist_ok=True)
    payload = {
        "model": model,
        "version": MODEL_VERSION,
        "n_samples": X_train.shape[0],
        "n_features": X_train.shape[1],
        "features": [
            "access_count",
            "failed_attempt_count",
            "transfer_count",
            "verification_failure_count",
            "unique_actor_count",
            "unique_role_count",
            "action_frequency",
            "min_time_between_actions",
            "unusual_hour_ratio",
            "repeated_action_burst",
            "unexpected_role_action",
            "custody_sequence_irregularity",
        ]
    }
    joblib.dump(payload, MODEL_FILE)
    print(f"[ML Train] Model successfully serialized to {MODEL_FILE}")

    # Self-test validation
    normal_test = np.array([[3.0, 0.0, 2.0, 0.0, 3.0, 2.0, 4.0, 1800.0, 0.0, 1.0, 0.0, 0.0]])
    anom_test   = np.array([[60.0, 8.0, 8.0, 3.0, 1.0, 1.0, 150.0, 0.4, 0.9, 7.0, 2.0, 3.0]])

    score_normal = -model.score_samples(normal_test)[0]
    score_anom   = -model.score_samples(anom_test)[0]
    print(f"[ML Train] Sanity check: Normal sample score = {score_normal:.3f} | Anomalous sample score = {score_anom:.3f}")
    assert score_anom > score_normal, "Anomalous sample must receive higher anomaly score!"
    print("[ML Train] Sanity check PASSED! Model ready for inference.")
    return True


if __name__ == "__main__":
    train_isolation_forest()
