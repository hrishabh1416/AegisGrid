"""AegisGrid Isolation Forest Anomaly Detection Module.

Wraps scikit-learn's ``IsolationForest`` in a domain-specific
``AnomalyDetector`` class that:

1. Pre-trains on a synthetic baseline of normal telemetry patterns plus
   deliberate outlier injections so the model is production-ready at boot.
2. Exposes a single ``predict()`` method that accepts a parsed log dict and
   returns ``(anomaly_score, classification_status)``.
3. Reads threshold / contamination parameters from centralised
   ``Settings`` so operators can tune without code changes.
"""

from __future__ import annotations

import logging
from typing import Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from app.core.config import settings
from app.ml.pipeline import (
    ASSETS_MAP,
    USERS_MAP,
    extract_features,
)

logger = logging.getLogger("aegisgrid.ml.isolation")


class AnomalyDetector:
    """Stateful Isolation Forest anomaly scorer for AegisGrid telemetry.

    Attributes
    ----------
    model : IsolationForest
        The underlying scikit-learn estimator.
    trained : bool
        ``True`` once ``_pretrain_baseline`` has fitted the model.
    threshold : float
        Decision-function cutoff below which an event is flagged as
        ``CRITICAL_ANOMALY``.  Sourced from ``settings.anomaly_threshold``.
    """

    def __init__(self) -> None:
        self.threshold: float = settings.anomaly_threshold
        self.model: IsolationForest = IsolationForest(
            contamination=settings.contamination_rate,
            random_state=42,
        )
        self.trained: bool = False
        self._pretrain_baseline()

    # ── Synthetic Baseline Training ─────────────────────────────────────

    def _pretrain_baseline(self) -> None:
        """Generate synthetic telemetry and fit the model at startup.

        Creates 1 000 normal-distribution events mirroring business-hours
        traffic patterns and injects 15 extreme-volume outliers to anchor
        the decision boundary.
        """
        rng = np.random.default_rng(seed=42)
        # -- keep legacy np.random.seed for exact reproducibility with
        #    the old ml_core.py training data --
        np.random.seed(42)
        num_samples = 1000

        hours = np.random.randint(8, 18, size=num_samples)
        days = np.random.randint(0, 5, size=num_samples)

        assets, users, bytes_transferred = [], [], []

        for _ in range(num_samples):
            rand_choice = np.random.rand()
            if rand_choice < 0.3:
                assets.append(ASSETS_MAP["GATEWAY-01"])
                users.append(USERS_MAP["user_alpha"])
                bytes_transferred.append(np.random.uniform(5_000, 1_000_000))
            elif rand_choice < 0.6:
                assets.append(ASSETS_MAP["DATABASE-CORE"])
                users.append(USERS_MAP["billing_svc"])
                bytes_transferred.append(np.random.uniform(10_000, 5_000_000))
            elif rand_choice < 0.8:
                assets.append(ASSETS_MAP["BILLING-SRV"])
                users.append(USERS_MAP["billing_svc"])
                bytes_transferred.append(np.random.uniform(2_000, 2_000_000))
            else:
                assets.append(ASSETS_MAP["ADMIN-GATEWAY"])
                users.append(USERS_MAP["admin_svc"])
                bytes_transferred.append(np.random.uniform(10_000, 10_000_000))

        df_normal = pd.DataFrame(
            {
                "hour": hours,
                "day": days,
                "asset_encoded": assets,
                "user_encoded": users,
                "bytes_log": np.log1p(bytes_transferred),
            }
        )

        # Deliberate outliers — off-hours, massive byte volumes
        anom_hours = np.random.randint(0, 6, size=15)
        anom_days = np.random.randint(0, 7, size=15)
        anom_assets = np.random.randint(0, 4, size=15)
        anom_users = np.random.randint(0, 4, size=15)
        anom_bytes = np.log1p(
            np.random.uniform(100_000_000, 10_000_000_000, size=15)
        )

        df_anom = pd.DataFrame(
            {
                "hour": anom_hours,
                "day": anom_days,
                "asset_encoded": anom_assets,
                "user_encoded": anom_users,
                "bytes_log": anom_bytes,
            }
        )

        df_train = pd.concat([df_normal, df_anom], ignore_index=True)
        self.model.fit(df_train)
        self.trained = True

        logger.info(
            "IsolationForest trained on %d events (incl. 15 outlier injections).",
            len(df_train),
        )

    # ── Prediction ──────────────────────────────────────────────────────

    def predict(self, parsed_log: dict) -> Tuple[float, str]:
        """Score a single parsed telemetry event.

        Parameters
        ----------
        parsed_log:
            Dict produced by :func:`app.ml.pipeline.parse_log`.

        Returns
        -------
        tuple[float, str]
            ``(raw_decision_score, classification)`` where classification
            is ``"CRITICAL_ANOMALY"`` when the score falls below
            ``self.threshold`` (default -0.02) *or* the model predicts -1,
            otherwise ``"SECURE"``.

        Raises
        ------
        RuntimeError
            If the model has not been trained yet.
        """
        if not self.trained:
            raise RuntimeError(
                "AnomalyDetector.predict() called before model training."
            )

        features = extract_features(parsed_log)
        prediction: int = int(self.model.predict(features)[0])
        raw_score: float = float(self.model.decision_function(features)[0])

        is_anomaly = (prediction == -1) or (raw_score < self.threshold)
        status = "CRITICAL_ANOMALY" if is_anomaly else "SECURE"

        logger.debug(
            "Score %.6f | prediction %d | status %s | asset %s",
            raw_score,
            prediction,
            status,
            parsed_log.get("source_asset", "?"),
        )

        return raw_score, status
