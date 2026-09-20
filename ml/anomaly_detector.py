"""
ForensicChain v2.4.1 — Isolation Forest Anomaly Detector
Unsupervised behavioral anomaly detector for evidence access, custody, and transfer patterns.
Advisory and investigative aid only; never replaces cryptographic blockchain verification.
"""

import os
import joblib
import numpy as np

MODEL_DIR = os.path.join(os.path.dirname(__file__), "model")
EVIBLOCK_MODEL_FILE = os.path.join(MODEL_DIR, "eviblock_isolation_forest.joblib")
BACKUP_MODEL_FILE = os.path.join(MODEL_DIR, "isolation_forest.joblib")
MODEL_FILE = EVIBLOCK_MODEL_FILE if os.path.exists(EVIBLOCK_MODEL_FILE) else BACKUP_MODEL_FILE
MODEL_VERSION = "v2.0-eviblock-isolation-forest"


class AnomalyDetector:
    _instance = None

    def __init__(self, model_path=None):
        self.model_path = model_path or MODEL_FILE
        self.model = None
        self.model_version = MODEL_VERSION
        self.feature_names = []
        self.dataset_info = None
        self.load_model()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def load_model(self):
        """Loads serialized Isolation Forest model from disk if available."""
        target_path = self.model_path
        if not os.path.exists(target_path) and os.path.exists(BACKUP_MODEL_FILE):
            target_path = BACKUP_MODEL_FILE

        if os.path.exists(target_path):
            try:
                loaded = joblib.load(target_path)
                if isinstance(loaded, dict) and "model" in loaded:
                    self.model = loaded["model"]
                    self.model_version = loaded.get("version", MODEL_VERSION)
                    self.feature_names = loaded.get("feature_names", loaded.get("features", []))
                    self.dataset_info = loaded.get("dataset_info")
                else:
                    self.model = loaded
                return True
            except Exception as e:
                print(f"[ML Anomaly Detector] Warning: Failed to load model from {target_path}: {e}")
                self.model = None
                return False
        else:
            self.model = None
            return False

    @property
    def is_available(self):
        return self.model is not None

    def predict(self, feature_vector, explanations=None):
        """
        Analyzes a 12-feature vector and returns anomaly diagnostics.

        Returns:
            dict with:
                - available: bool
                - anomaly_score: float (0.0 to 1.0, higher = more anomalous)
                - is_anomaly: bool
                - risk_level: "LOW" | "MEDIUM" | "HIGH"
                - status: "Suspicious Activity" | "Normal Activity"
                - reasons: list of human-readable explanations
                - model_version: str
        """
        if not self.is_available:
            # Graceful fallback when model is not available
            return {
                "available": False,
                "message": "AI analysis unavailable (model not trained or loaded)",
                "anomaly_score": 0.0,
                "is_anomaly": False,
                "risk_level": "UNKNOWN",
                "status": "AI Analysis Unavailable",
                "reasons": ["Isolation Forest model is not currently initialized."],
                "model_version": self.model_version,
            }

        explanations = list(explanations or [])
        X = np.array([feature_vector], dtype=float)

        try:
            # IsolationForest predict returns -1 for outliers/anomalies, +1 for inliers
            raw_pred = self.model.predict(X)[0]
            # score_samples returns opposite of anomaly score; lower = more abnormal
            # Typical output is around -0.7 to -0.3.
            raw_score = self.model.score_samples(X)[0]

            # Normalize raw score to a human-friendly [0.0, 1.0] scale
            # In scikit-learn, offset_ is typically -0.5. Values < -0.5 are anomalies.
            offset = getattr(self.model, "offset_", -0.5)
            # Distance from offset normalized
            normalized_score = float(np.clip(0.5 - (raw_score - offset), 0.05, 0.99))

            # Hard override based on critical red flags (e.g. sequence irregularity or tamper failures)
            # feature indices: [3] = verification_failure_count, [11] = custody_sequence_irregularity
            verification_failures = feature_vector[3] if len(feature_vector) > 3 else 0
            seq_irregularities = feature_vector[11] if len(feature_vector) > 11 else 0

            is_anomaly = bool(raw_pred == -1 or verification_failures > 0 or seq_irregularities > 0 or normalized_score >= 0.65)

            if is_anomaly and normalized_score < 0.65:
                normalized_score = max(normalized_score, 0.72)

            # Categorize Risk Level
            if normalized_score >= 0.70 or is_anomaly:
                risk_level = "HIGH"
                status = "Suspicious Activity"
            elif normalized_score >= 0.45:
                risk_level = "MEDIUM"
                status = "Normal Activity (Elevated Variance)"
            else:
                risk_level = "LOW"
                status = "Normal Activity"

            # Ensure explanatory reasons reflect status
            if status == "Suspicious Activity" and (not explanations or explanations == ["Custody, verification, and access history follow expected operational patterns."]):
                explanations = ["Multi-dimensional custody behavior deviates significantly from baseline behavioral profile."]

            return {
                "available": True,
                "anomaly_score": round(normalized_score, 2),
                "is_anomaly": is_anomaly,
                "risk_level": risk_level,
                "status": status,
                "reasons": explanations,
                "model_version": self.model_version,
            }

        except Exception as e:
            return {
                "available": False,
                "error": str(e),
                "message": "AI analysis unavailable due to scoring error",
                "anomaly_score": 0.0,
                "is_anomaly": False,
                "risk_level": "UNKNOWN",
                "status": "AI Analysis Unavailable",
                "reasons": [f"Feature evaluation exception: {e}"],
                "model_version": self.model_version,
            }


# Singleton instance
detector = AnomalyDetector.get_instance()
