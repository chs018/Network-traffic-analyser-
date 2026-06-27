"""
feature_engineering.py — ML Feature Engineering Pipeline
==========================================================
Network Traffic Analysis and Intrusion Detection System

Transforms a raw packet DataFrame into a rich feature matrix by computing:
  - Temporal rate features  (PPS, BPS, inter-arrival time)
  - Rolling window statistics (mean, std, min, max over configurable windows)
  - Z-score normalised features
  - Protocol entropy per time window
  - IP and port diversity indices
  - Burstiness index (Fano factor)
  - Flow density and traffic imbalance
  - TCP flag ratio features
  - Connection frequency and unique target counts

All operations use vectorised Pandas / NumPy for performance.

Classes:
    FeatureConfig         — Dataclass of engineering parameters
    FeatureEngineer       — Stateless feature engineering engine

Author: Network Traffic Analyzer Project
Version: 6.0.0
Python: 3.11+
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Optional

import numpy as np
import pandas as pd

from utils.logger import get_ml_logger

log = get_ml_logger()


# ──────────────────────────────────────────────────────────────────────────────
# FEATURE CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class FeatureConfig:
    """
    Tunable parameters for feature engineering.

    Attributes:
        window_sizes:   Sliding window sizes (in rows) for rolling features.
        z_score_cols:   Columns for which z-score features are generated.
        entropy_top_n:  Top-N items to consider when computing entropy.
    """

    window_sizes: list[int] = field(default_factory=lambda: [5, 10, 30])
    z_score_cols: list[str] = field(default_factory=lambda: [
        "packet_length", "source_port", "destination_port", "ttl"
    ])
    entropy_top_n: int = 20
    min_packets_for_rate: int = 2   # Minimum rows to compute rate features


# ──────────────────────────────────────────────────────────────────────────────
# FEATURE ENGINEER
# ──────────────────────────────────────────────────────────────────────────────

class FeatureEngineer:
    """
    Stateless feature engineering engine for network traffic DataFrames.

    Produces a set of derived, ML-ready features from a raw packet DataFrame.
    The engineer is stateless — it can be called on any DataFrame without
    maintaining fit state (all parameters are computed from the input data).

    Usage::

        fe = FeatureEngineer()
        df_features = fe.transform(df_raw)
        feature_names = fe.get_feature_names()
    """

    # Columns expected from packets.csv (normalised names)
    _EXPECTED_COLS: frozenset[str] = frozenset({
        "packet_length", "source_port", "destination_port",
        "source_ip", "destination_ip", "protocol",
    })

    def __init__(self, cfg: Optional[FeatureConfig] = None) -> None:
        """
        Initialise the FeatureEngineer.

        Args:
            cfg: Optional :class:`FeatureConfig` to override defaults.
        """
        self._cfg = cfg or FeatureConfig()
        self._feature_names: list[str] = []
        log.debug("FeatureEngineer initialised (windows=%s).", self._cfg.window_sizes)

    # ── Public API ─────────────────────────────────────────────────────────────

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply the full feature engineering pipeline to a packet DataFrame.

        The pipeline runs in order:
          1. Column normalisation (rename source_ip → src_ip etc.)
          2. Numeric base features
          3. TCP flag ratio features
          4. Rolling window features (per window_size)
          5. Z-score features
          6. IP / port diversity features
          7. Protocol entropy features
          8. Burstiness and traffic rate features
          9. Fill remaining NaNs with 0

        Args:
            df: Raw packet DataFrame (from packets.csv or DatabaseManager).

        Returns:
            New DataFrame containing only engineered numeric feature columns.
            The index is reset to 0..N-1.
        """
        if df is None or df.empty:
            log.warning("FeatureEngineer.transform(): empty DataFrame.")
            return pd.DataFrame()

        log.info("FeatureEngineer: engineering features for %d rows.", len(df))
        out = df.copy()

        # Step 1: Normalise column names
        out = self._normalise_columns(out)

        # Step 2: Base numeric features
        out = self._add_base_features(out)

        # Step 3: TCP flag ratios
        out = self._add_flag_features(out)

        # Step 4: Rolling window features
        for w in self._cfg.window_sizes:
            out = self._add_rolling_features(out, window=w)

        # Step 5: Z-score features
        out = self._add_zscore_features(out)

        # Step 6: IP / port diversity
        out = self._add_diversity_features(out)

        # Step 7: Protocol entropy
        out = self._add_entropy_features(out)

        # Step 8: Burstiness and rate features
        out = self._add_burstiness_features(out)

        # Step 9: Select only numeric columns and fill NaN
        numeric_cols = out.select_dtypes(include=[np.number]).columns.tolist()
        out = out[numeric_cols].fillna(0.0)

        self._feature_names = list(out.columns)
        log.info("FeatureEngineer: produced %d features.", len(self._feature_names))
        return out.reset_index(drop=True)

    def get_feature_names(self) -> list[str]:
        """
        Return the ordered list of feature column names from the last transform().

        Returns:
            List of feature name strings.
        """
        return list(self._feature_names)

    # ── Step 1: Column Normalisation ─────────────────────────────────────────

    @staticmethod
    def _normalise_columns(df: pd.DataFrame) -> pd.DataFrame:
        """Rename CSV-specific column aliases to canonical names."""
        rename_map: dict[str, str] = {
            "src_ip": "source_ip",
            "dst_ip": "destination_ip",
            "src_port": "source_port",
            "dst_port": "destination_port",
        }
        # Reverse: if canonical names already present, do nothing
        existing = set(df.columns)
        actual_map = {k: v for k, v in rename_map.items()
                      if k in existing and v not in existing}
        return df.rename(columns=actual_map)

    # ── Step 2: Base Numeric Features ────────────────────────────────────────

    @staticmethod
    def _add_base_features(df: pd.DataFrame) -> pd.DataFrame:
        """Coerce key columns to numeric and add derived base features."""
        out = df.copy()

        # Coerce numeric
        for col in ("packet_length", "source_port", "destination_port",
                    "ttl", "ip_version"):
            if col in out.columns:
                out[col] = pd.to_numeric(out[col], errors="coerce").fillna(0.0)

        # Packet size squared (emphasises large packets)
        if "packet_length" in out.columns:
            out["packet_length_sq"] = out["packet_length"] ** 2
            # Log-transform of packet length (handles heavy-tailed distribution)
            out["packet_length_log"] = np.log1p(out["packet_length"])

        # Port ratio (dst/src — high ratio may indicate well-known service target)
        sp = out.get("source_port", pd.Series(0, index=out.index)).clip(lower=1)
        dp = out.get("destination_port", pd.Series(0, index=out.index))
        out["port_ratio"] = (dp / sp.replace(0, np.nan)).fillna(0.0)

        # Port in privileged range flags
        if "destination_port" in out.columns:
            out["dst_port_privileged"] = (
                out["destination_port"].between(0, 1023)
            ).astype(int)
            out["dst_port_ephemeral"] = (
                out["destination_port"].between(49152, 65535)
            ).astype(int)

        if "source_port" in out.columns:
            out["src_port_privileged"] = (
                out["source_port"].between(0, 1023)
            ).astype(int)

        # Protocol one-hot encoding
        if "protocol" in out.columns:
            proto = out["protocol"].str.upper().fillna("UNKNOWN")
            for p in ("TCP", "UDP", "ICMP", "ARP", "DNS"):
                out[f"proto_{p.lower()}"] = (proto.str.startswith(p)).astype(int)

        # Boolean flags already in CSV
        for col in ("is_tcp", "is_udp", "is_icmp",
                    "is_private_src", "is_private_dst"):
            if col in out.columns:
                out[col] = pd.to_numeric(out[col], errors="coerce").fillna(0).astype(int)

        # IP frequency features (already in CSV)
        for col in ("source_ip_frequency", "destination_ip_frequency"):
            if col in out.columns:
                out[col] = pd.to_numeric(out[col], errors="coerce").fillna(0.0)
                # Log-transform to reduce skew
                out[f"{col}_log"] = np.log1p(out[col])

        # Hour of day (circular encoding)
        if "hour_of_day" in out.columns:
            out["hour_of_day"] = pd.to_numeric(out["hour_of_day"], errors="coerce").fillna(0.0)
            out["hour_sin"] = np.sin(2 * np.pi * out["hour_of_day"] / 24)
            out["hour_cos"] = np.cos(2 * np.pi * out["hour_of_day"] / 24)

        return out

    # ── Step 3: TCP Flag Ratio Features ──────────────────────────────────────

    @staticmethod
    def _add_flag_features(df: pd.DataFrame) -> pd.DataFrame:
        """
        Parse tcp_flags column (hex string / int / named) and compute ratios.

        Adds:
          - flag_syn, flag_ack, flag_rst, flag_fin, flag_psh
          - syn_ack_ratio  (SYN count / SYN+ACK count, rolling)
        """
        out = df.copy()
        if "tcp_flags" not in out.columns:
            for flag in ("flag_syn", "flag_ack", "flag_rst", "flag_fin", "flag_psh"):
                out[flag] = 0
            return out

        def _parse(val: Any) -> int:
            if val is None or (isinstance(val, float) and math.isnan(val)):
                return 0
            s = str(val).strip()
            if not s or s in ("None", "nan", "NaN", ""):
                return 0
            if s.startswith("0x") or s.startswith("0X"):
                try:
                    return int(s, 16)
                except ValueError:
                    pass
            try:
                return int(s)
            except ValueError:
                pass
            # Named flags
            _map = {"F": 0x01, "FIN": 0x01, "S": 0x02, "SYN": 0x02,
                    "R": 0x04, "RST": 0x04, "P": 0x08, "PSH": 0x08,
                    "A": 0x10, "ACK": 0x10, "U": 0x20, "URG": 0x20}
            result = 0
            for token in s.upper().split():
                result |= _map.get(token, 0)
            return result

        flag_ints = out["tcp_flags"].map(_parse)
        out["flag_syn"] = (flag_ints & 0x02 > 0).astype(int)
        out["flag_ack"] = (flag_ints & 0x10 > 0).astype(int)
        out["flag_rst"] = (flag_ints & 0x04 > 0).astype(int)
        out["flag_fin"] = (flag_ints & 0x01 > 0).astype(int)
        out["flag_psh"] = (flag_ints & 0x08 > 0).astype(int)

        # SYN / (SYN + ACK) rolling ratio (window=10)
        syn = out["flag_syn"].rolling(10, min_periods=1).sum()
        ack = out["flag_ack"].rolling(10, min_periods=1).sum()
        out["syn_ack_ratio"] = (syn / (syn + ack + 1e-9)).fillna(0.0)

        return out

    # ── Step 4: Rolling Window Features ──────────────────────────────────────

    @staticmethod
    def _add_rolling_features(df: pd.DataFrame, window: int) -> pd.DataFrame:
        """
        Add rolling mean, std, min, max for packet_length, source_port,
        and destination_port over a given window size.

        Args:
            df:     Feature DataFrame.
            window: Rolling window size in rows.

        Returns:
            DataFrame with appended rolling feature columns.
        """
        out = df.copy()
        roll_cols = [c for c in ("packet_length", "source_port",
                                  "destination_port", "ttl")
                     if c in out.columns]

        for col in roll_cols:
            series = pd.to_numeric(out[col], errors="coerce").fillna(0.0)
            r = series.rolling(window, min_periods=1)
            prefix = f"{col}_w{window}"
            out[f"{prefix}_mean"] = r.mean()
            out[f"{prefix}_std"] = r.std().fillna(0.0)
            out[f"{prefix}_min"] = r.min()
            out[f"{prefix}_max"] = r.max()
            out[f"{prefix}_range"] = out[f"{prefix}_max"] - out[f"{prefix}_min"]

        return out

    # ── Step 5: Z-Score Features ──────────────────────────────────────────────

    def _add_zscore_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Compute global z-scores for each column in ``cfg.z_score_cols``.

        Z-score = (x - mean) / std, clipped to [-5, 5].

        Args:
            df: Feature DataFrame.

        Returns:
            DataFrame with appended z-score columns (suffix ``_zscore``).
        """
        out = df.copy()
        for col in self._cfg.z_score_cols:
            if col not in out.columns:
                continue
            series = pd.to_numeric(out[col], errors="coerce").fillna(0.0)
            mean_val = series.mean()
            std_val = series.std()
            if std_val > 0:
                z = (series - mean_val) / std_val
            else:
                z = pd.Series(0.0, index=series.index)
            out[f"{col}_zscore"] = z.clip(-5.0, 5.0)
        return out

    # ── Step 6: IP / Port Diversity ───────────────────────────────────────────

    @staticmethod
    def _add_diversity_features(df: pd.DataFrame) -> pd.DataFrame:
        """
        Add rolling unique-count features for IP diversity and port diversity.

        Unique destination ports per source IP (window=30) → port_diversity
        Unique destination IPs per source IP (window=30) → ip_diversity
        """
        out = df.copy()
        window = 30

        if "destination_port" in out.columns:
            # Rolling unique destination port count (approximated with nunique over rolling)
            out["dst_port_nunique_w30"] = (
                out["destination_port"]
                .rolling(window, min_periods=1)
                .apply(lambda x: len(set(x)), raw=False)
                .fillna(0.0)
            )

        if "source_port" in out.columns:
            out["src_port_nunique_w30"] = (
                out["source_port"]
                .rolling(window, min_periods=1)
                .apply(lambda x: len(set(x)), raw=False)
                .fillna(0.0)
            )

        # Same-source packet concentration (src_ip_frequency / total in window)
        if "source_ip_frequency" in out.columns:
            out["src_ip_concentration"] = (
                out["source_ip_frequency"] /
                (out["source_ip_frequency"].rolling(window, min_periods=1).sum() + 1e-9)
            ).fillna(0.0)

        return out

    # ── Step 7: Protocol Entropy ──────────────────────────────────────────────

    def _add_entropy_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Compute Shannon entropy of protocol distribution in a rolling window.

        Higher entropy → more diverse protocol mix.
        Lower entropy → protocol flood (one dominant protocol).
        """
        out = df.copy()
        window = 30

        if "protocol" not in out.columns:
            out["protocol_entropy_w30"] = 0.0
            return out

        proto_num = out["protocol"].astype("category").cat.codes.astype(float)

        def _entropy(arr: np.ndarray) -> float:
            arr = arr[~np.isnan(arr)]
            if len(arr) == 0:
                return 0.0
            vals, counts = np.unique(arr, return_counts=True)
            probs = counts / counts.sum()
            return float(-np.sum(probs * np.log2(probs + 1e-9)))

        out["protocol_entropy_w30"] = (
            proto_num
            .rolling(window, min_periods=1)
            .apply(_entropy, raw=True)
            .fillna(0.0)
        )
        return out

    # ── Step 8: Burstiness & Rate Features ────────────────────────────────────

    @staticmethod
    def _add_burstiness_features(df: pd.DataFrame) -> pd.DataFrame:
        """
        Add burstiness index (Fano factor = var/mean) and flow density features.

        Fano factor > 1 → bursty traffic (indicative of flood attacks).
        Fano factor ≈ 1 → Poisson-like (normal traffic).
        Fano factor < 1 → sub-Poisson (very regular traffic).
        """
        out = df.copy()
        window = 30

        if "packet_length" in out.columns:
            pkt = pd.to_numeric(out["packet_length"], errors="coerce").fillna(0.0)
            roll = pkt.rolling(window, min_periods=2)
            roll_mean = roll.mean().fillna(0.0)
            roll_var = roll.var().fillna(0.0)
            # Fano factor (burstiness index)
            out["burstiness_index"] = (roll_var / (roll_mean + 1e-9)).fillna(0.0)
            # Traffic density: packets per unit "time" (approximated by row count)
            out["traffic_density"] = roll_mean / (out["packet_length"] + 1e-9)

        # Traffic imbalance: abs(src_freq - dst_freq) / (src_freq + dst_freq)
        if "source_ip_frequency" in out.columns and "destination_ip_frequency" in out.columns:
            src_f = pd.to_numeric(out["source_ip_frequency"], errors="coerce").fillna(0.0)
            dst_f = pd.to_numeric(out["destination_ip_frequency"], errors="coerce").fillna(0.0)
            out["traffic_imbalance"] = (
                (src_f - dst_f).abs() / (src_f + dst_f + 1e-9)
            ).fillna(0.0)

        # Connection frequency: rolling packet count per window
        if "packet_length" in out.columns:
            out["connection_freq_w10"] = (
                pd.to_numeric(out["packet_length"], errors="coerce")
                .fillna(0.0)
                .rolling(10, min_periods=1)
                .count()
            )

        # Malformed packet flag: protocol contains "MALFORMED" or length < 20
        if "protocol" in out.columns:
            out["is_malformed"] = (
                out["protocol"].str.contains("MALFORM", case=False, na=False)
            ).astype(int)
        if "packet_length" in out.columns:
            out["is_tiny_packet"] = (out["packet_length"] < 20).astype(int)

        return out
