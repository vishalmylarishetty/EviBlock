"""
ForensicChain / EviBlock v2.5.0 — EviBlock-Specific Isolation Forest Training Pipeline
===================================================================================
Generates a controlled, simulated EviBlock evidence custody behavioral dataset
based strictly on the application's actual 12-feature definitions in ml/feature_engineering.py.
Trains and serializes the new EviBlock Isolation Forest model to:
    ml/model/eviblock_isolation_forest.joblib

IMPORTANT:
- Labeled explicitly as controlled/simulated training data. Not claimed as real-world data.
- Keeps ml/model/isolation_forest.joblib intact as backup.
- Uses exact 12 EviBlock features in identical order as ml/feature_engineering.py.
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    accuracy_score,
)

# ── Paths & Metadata ────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "model")
NEW_MODEL_FILE = os.path.join(MODEL_DIR, "eviblock_isolation_forest.joblib")
DATASET_CSV_FILE = os.path.join(BASE_DIR, "eviblock_controlled_dataset.csv")
MODEL_VERSION = "v2.0-eviblock-isolation-forest"

# Exact 12 features from ml/feature_engineering.py in exact order
FEATURE_NAMES = [
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


def generate_eviblock_controlled_dataset(n_normal=850, n_anomalies=150, random_state=42):
    """
    Generates a controlled, simulated EviBlock evidence custody dataset.
    Explicitly labeled as controlled simulated training data based strictly on
    the application's actual feature definitions in ml/feature_engineering.py.
    """
    rng = np.random.RandomState(random_state)

    # ── 1. Normal Operational Baseline Patterns (n_normal = 850) ──
    normal_data = []
    for _ in range(n_normal):
        access_count = float(rng.poisson(lam=4) + 1)                      # 1-10 accesses in lifecycle
        failed_attempts = float(rng.choice([0, 0, 0, 0, 1]))             # 0, rare typo (1)
        transfers = float(rng.choice([1, 2, 3, 4], p=[0.4, 0.35, 0.2, 0.05])) # 1-4 standard transfers
        verif_failures = 0.0                                             # Legitimate evidence has 0 failures
        actors = float(rng.choice([2, 3, 4, 5], p=[0.25, 0.45, 0.25, 0.05])) # 2-5 distinct officers
        roles = float(rng.choice([2, 3, 4], p=[0.35, 0.50, 0.15]))       # police, analyst, court, witness
        freq = float(rng.gamma(shape=2.5, scale=1.5) + 0.5)              # 1-8 actions/day
        min_time = float(rng.uniform(180.0, 14400.0))                     # 3 minutes to 4 hours between actions
        unusual_hour = float(rng.beta(a=0.5, b=6.0) * 0.12)              # 0-10% off hours
        burst = float(rng.choice([1, 1, 1, 2], p=[0.6, 0.25, 0.1, 0.05])) # max 1-2 repeats
        unexpected_role = 0.0                                            # expected authorized roles
        seq_irreg = 0.0                                                  # valid linear custody progression

        normal_data.append([
            access_count, failed_attempts, transfers, verif_failures,
            actors, roles, freq, min_time, unusual_hour, burst,
            unexpected_role, seq_irreg
        ])

    # ── 2. Controlled Realistic Suspicious Scenarios (n_anomalies = 150) ──
    anomalies_data = []

    # Scenario 1: Repeated Failed Verification & Cryptographic Tamper Attempts (25)
    for _ in range(25):
        anomalies_data.append([
            float(rng.randint(3, 12)),
            float(rng.randint(1, 4)),
            float(rng.randint(1, 4)),
            float(rng.randint(2, 6)),                 # Multiple cryptographic verification failures!
            float(rng.randint(2, 4)),
            float(rng.randint(2, 3)),
            float(rng.uniform(3.0, 15.0)),
            float(rng.uniform(60.0, 1200.0)),
            float(rng.uniform(0.0, 0.20)),
            float(rng.choice([1, 2])),
            0.0,
            0.0
        ])

    # Scenario 2: Abnormal Custody Sequence Progression & Irregular Jumps (25)
    for _ in range(25):
        anomalies_data.append([
            float(rng.randint(2, 8)),
            0.0,
            float(rng.randint(1, 4)),
            0.0,
            float(rng.randint(2, 4)),
            float(rng.randint(2, 3)),
            float(rng.uniform(2.0, 12.0)),
            float(rng.uniform(120.0, 3600.0)),
            float(rng.uniform(0.0, 0.15)),
            1.0,
            float(rng.randint(1, 3)),                 # Unexpected role actions
            float(rng.randint(2, 5))                  # Severe out-of-order sequence transitions!
        ])

    # Scenario 3: Off-Hours Nocturnal Evidence Access / Lone Exfiltration (25)
    for _ in range(25):
        anomalies_data.append([
            float(rng.randint(12, 35)),
            float(rng.randint(1, 5)),
            float(rng.randint(2, 6)),
            0.0,
            1.0,                                      # Rogue lone actor without corroboration
            1.0,
            float(rng.uniform(15.0, 45.0)),
            float(rng.uniform(30.0, 240.0)),
            float(rng.uniform(0.70, 1.0)),            # >70% middle of night (23:00-05:00)!
            float(rng.randint(2, 5)),
            float(rng.choice([0, 1])),
            0.0
        ])

    # Scenario 4: Rapid Automated Bursts & Sub-Second Scraping/Access (25)
    for _ in range(25):
        anomalies_data.append([
            float(rng.randint(30, 85)),               # Excessive access count
            float(rng.randint(2, 7)),
            float(rng.randint(5, 12)),                # High transfers
            0.0,
            float(rng.randint(1, 2)),
            1.0,
            float(rng.uniform(60.0, 200.0)),          # Extreme action frequency
            float(rng.uniform(0.1, 2.5)),             # Sub-second intervals!
            float(rng.uniform(0.1, 0.35)),
            float(rng.randint(5, 12)),                # High repeated burst
            0.0,
            0.0
        ])

    # Scenario 5: Unauthorized Permission Probing & Access Denial Spikes (25)
    for _ in range(25):
        anomalies_data.append([
            float(rng.randint(25, 70)),
            float(rng.randint(8, 22)),                # Repeated permission denied / failed attempts!
            float(rng.randint(1, 3)),
            0.0,
            float(rng.randint(1, 2)),
            1.0,
            float(rng.uniform(30.0, 90.0)),
            float(rng.uniform(5.0, 60.0)),
            float(rng.uniform(0.15, 0.50)),
            float(rng.randint(3, 8)),
            float(rng.randint(1, 3)),                 # Unauthorized role attempts
            0.0
        ])

    # Scenario 6: Combined Multi-Vector High-Risk Evidence Tamper (25)
    for _ in range(n_anomalies - len(anomalies_data)):
        anomalies_data.append([
            float(rng.randint(20, 60)),
            float(rng.randint(3, 10)),
            float(rng.randint(4, 8)),
            float(rng.randint(1, 4)),                 # Tamper failure
            float(rng.randint(1, 3)),
            float(rng.randint(1, 2)),
            float(rng.uniform(25.0, 80.0)),
            float(rng.uniform(1.0, 15.0)),
            float(rng.uniform(0.50, 0.90)),           # Nocturnal
            float(rng.randint(4, 9)),
            float(rng.randint(1, 3)),                 # Role mismatch
            float(rng.randint(1, 3))                  # Sequence irregularity
        ])

    X_normal = np.array(normal_data, dtype=float)
    X_anom = np.array(anomalies_data, dtype=float)

    X = np.vstack([X_normal, X_anom])
    # Ground truth: 0 = Normal, 1 = Suspicious/Anomaly
    y = np.array([0] * len(X_normal) + [1] * len(X_anom), dtype=int)

    return X, y


def train_and_evaluate_eviblock_model():
    """
    Executes the training and held-out evaluation of the EviBlock Isolation Forest.
    Saves model to ml/model/eviblock_isolation_forest.joblib.
    """
    print("[EviBlock Train] Generating controlled simulated EviBlock training dataset...")
    X, y = generate_eviblock_controlled_dataset(n_normal=850, n_anomalies=150, random_state=42)

    # Export dataset to CSV for reproducibility
    df_data = pd.DataFrame(X, columns=FEATURE_NAMES)
    df_data["target_anomaly"] = y
    df_data.to_csv(DATASET_CSV_FILE, index=False)
    print(f"[EviBlock Train] Controlled dataset exported to: {DATASET_CSV_FILE}")

    # 80/20 train-test split stratified by class
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    contamination = float((y_train == 1).sum() / len(y_train))
    print(f"[EviBlock Train] Training samples: {X_train.shape[0]}, Test samples: {X_test.shape[0]}")
    print(f"[EviBlock Train] Estimated training contamination: {contamination:.4f}")

    # Fit Isolation Forest
    model = IsolationForest(
        n_estimators=150,
        max_samples="auto",
        contamination=contamination,
        random_state=42,
        bootstrap=False,
    )
    model.fit(X_train)

    # Evaluate on held-out test fold
    raw_preds = model.predict(X_test)
    y_pred = np.where(raw_preds == -1, 1, 0)

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred))
    rec = float(recall_score(y_test, y_pred))
    f1 = float(f1_score(y_test, y_pred))
    cm = confusion_matrix(y_test, y_pred)

    print("\n" + "=" * 55)
    print("EviBlock Model Evaluation on Held-Out Test Fold (20%):")
    print("=" * 55)
    print(f"Accuracy:  {acc:.4f} ({acc * 100:.1f}%)")
    print(f"Precision: {prec:.4f} ({prec * 100:.1f}%)")
    print(f"Recall:    {rec:.4f} ({rec * 100:.1f}%)")
    print(f"F1-Score:  {f1:.4f} ({f1 * 100:.1f}%)")
    print("Confusion Matrix:")
    print("                 Pred Normal    Pred Anomaly")
    print(f"Actual Normal        {cm[0, 0]:<12} {cm[0, 1]:<12}")
    print(f"Actual Anomaly       {cm[1, 0]:<12} {cm[1, 1]:<12}")
    print("=" * 55 + "\n")

    # Serialize new model payload
    os.makedirs(MODEL_DIR, exist_ok=True)
    payload = {
        "model": model,
        "version": MODEL_VERSION,
        "feature_names": FEATURE_NAMES,
        "features": FEATURE_NAMES,
        "n_features": len(FEATURE_NAMES),
        "n_samples": int(X.shape[0]),
        "dataset_info": {
            "dataset_type": "controlled_eviblock_custody_simulation",
            "description": "Controlled EviBlock Evidence Custody Behavioral Dataset (Simulated)",
            "total_samples": int(X.shape[0]),
            "normal_samples": int((y == 0).sum()),
            "anomaly_samples": int((y == 1).sum()),
            "train_split": int(X_train.shape[0]),
            "test_split": int(X_test.shape[0]),
            "split_ratio": "80/20",
            "evaluation_metrics": {
                "accuracy": acc,
                "precision": prec,
                "recall": rec,
                "f1_score": f1,
                "confusion_matrix": {
                    "tn": int(cm[0, 0]),
                    "fp": int(cm[0, 1]),
                    "fn": int(cm[1, 0]),
                    "tp": int(cm[1, 1]),
                },
            },
        },
    }

    joblib.dump(payload, NEW_MODEL_FILE)
    print(f"[EviBlock Train] Model successfully serialized to: {NEW_MODEL_FILE}")

    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "confusion_matrix": cm,
        "model_file": NEW_MODEL_FILE,
        "n_samples": X.shape[0],
        "n_features": len(FEATURE_NAMES),
    }


if __name__ == "__main__":
    train_and_evaluate_eviblock_model()
