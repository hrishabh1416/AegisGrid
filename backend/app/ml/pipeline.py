"""AegisGrid Telemetry Log Pipeline — Parsing & Feature Extraction.

Converts raw syslog-formatted text strings into structured Python dicts and
then into numerical feature matrices suitable for the Isolation Forest model.

This module is intentionally model-free: it contains zero ML dependencies so
that it can be unit-tested, profiled, and reused independently.

Expected log format
-------------------
``TIMESTAMP [ASSET] USER BYTES STATUS``

Examples::

    2026-07-19T10:05:00Z [GATEWAY-01] admin_svc 150000 SUCCESS
    2026-07-19T03:12:44Z [DATABASE-CORE] backup_agent 5800000000 SUCCESS
"""

from __future__ import annotations

import datetime
import logging
import re
from typing import Dict, Optional

import numpy as np
import pandas as pd

logger = logging.getLogger("aegisgrid.ml.pipeline")

# ── Regex Pattern ───────────────────────────────────────────────────────────

LOG_REGEX: re.Pattern[str] = re.compile(
    r"(\S+) \[([^\]]+)\] (\S+) (\d+) (\S+)"
)

# ── Categorical Encoding Maps ──────────────────────────────────────────────

ASSETS_MAP: Dict[str, int] = {
    "GATEWAY-01": 0,
    "ADMIN-GATEWAY": 1,
    "BILLING-SRV": 2,
    "DATABASE-CORE": 3,
}
DEFAULT_ASSET_VAL: int = 4

USERS_MAP: Dict[str, int] = {
    "admin_svc": 0,
    "billing_svc": 1,
    "user_alpha": 2,
    "backup_agent": 3,
}
DEFAULT_USER_VAL: int = 4


# ── Public Functions ────────────────────────────────────────────────────────

def parse_log(log_line: str) -> Optional[dict]:
    """Parse a raw syslog line into a structured metadata dictionary.

    Parameters
    ----------
    log_line:
        A single whitespace-trimmed syslog line in the format
        ``TIMESTAMP [ASSET] USER BYTES STATUS``.

    Returns
    -------
    dict or None
        A dictionary with keys ``timestamp``, ``source_asset``,
        ``user_principal``, ``bytes_transferred``, and ``status``;
        or ``None`` if the line does not match the expected pattern.
    """
    match = LOG_REGEX.search(log_line.strip())
    if not match:
        logger.warning("Log line failed regex match: %.120s", log_line)
        return None

    timestamp_str, source_asset, user_principal, bytes_str, status = match.groups()

    # ── Timestamp normalisation ─────────────────────────────────────────
    try:
        timestamp = datetime.datetime.fromisoformat(
            timestamp_str.replace("Z", "+00:00")
        )
    except ValueError:
        logger.warning(
            "Unparseable timestamp '%s' — falling back to UTC now.", timestamp_str
        )
        timestamp = datetime.datetime.now(datetime.timezone.utc)

    # ── Bytes coercion ──────────────────────────────────────────────────
    try:
        bytes_transferred = int(bytes_str)
    except ValueError:
        bytes_transferred = 0

    return {
        "timestamp": timestamp,
        "source_asset": source_asset,
        "user_principal": user_principal,
        "bytes_transferred": bytes_transferred,
        "status": status,
    }


def extract_features(parsed_log: dict) -> pd.DataFrame:
    """Convert a parsed log dictionary into a single-row feature DataFrame.

    The feature vector consists of:

    +-----------------+--------------------------------------------+
    | Feature         | Description                                |
    +=================+============================================+
    | ``hour``        | Hour-of-day (0–23) from the log timestamp  |
    | ``day``         | Day-of-week (0=Mon … 6=Sun)                |
    | ``asset_encoded``| Integer-encoded asset identifier          |
    | ``user_encoded``| Integer-encoded user principal             |
    | ``bytes_log``   | ``log1p`` of bytes transferred             |
    +-----------------+--------------------------------------------+

    Parameters
    ----------
    parsed_log:
        Output of :func:`parse_log`.

    Returns
    -------
    pd.DataFrame
        A single-row DataFrame ready for ``model.predict()`` /
        ``model.decision_function()``.
    """
    dt = parsed_log["timestamp"]
    return pd.DataFrame(
        [
            {
                "hour": dt.hour,
                "day": dt.weekday(),
                "asset_encoded": ASSETS_MAP.get(
                    parsed_log["source_asset"], DEFAULT_ASSET_VAL
                ),
                "user_encoded": USERS_MAP.get(
                    parsed_log["user_principal"], DEFAULT_USER_VAL
                ),
                "bytes_log": float(np.log1p(parsed_log["bytes_transferred"])),
            }
        ]
    )
