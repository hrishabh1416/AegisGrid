"""AegisGrid ML sub-package.

Provides log parsing, feature extraction, and Isolation-Forest-based
anomaly detection for the cyber-resilience telemetry pipeline.

Public API
----------
- :func:`parse_log`        – Parse a raw syslog line into a structured dict.
- :func:`extract_features` – Convert a parsed log dict into a feature DataFrame.
- :class:`AnomalyDetector` – Stateful Isolation Forest scorer.
"""

from app.ml.pipeline import parse_log, extract_features  # noqa: F401
from app.ml.isolation import AnomalyDetector  # noqa: F401
