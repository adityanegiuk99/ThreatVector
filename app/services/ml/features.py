"""Feature engineering from the publication-time dataset table.

Design constraints:
  - Only publication-time fields (no KEV-derived columns, no post-publication NVD edits).
  - Categorical columns are one-hot encoded with fixed vocabularies so train and
    inference feature schemas match.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd

NUMERIC_FEATURES = [
    "cvss_base_score",
    "exploitability_score",
    "impact_score",
    "n_cwe",
    "n_references",
    "n_affected_products",
    "desc_len",
    "has_cwe",
    "scope_changed",
]

CATEGORICAL_FEATURES = {
    "attack_vector": ["ADJACENT_NETWORK", "LOCAL", "NETWORK", "PHYSICAL", None],
    "attack_complexity": ["HIGH", "LOW", None],
    "user_interaction": ["NONE", "REQUIRED", None],
    "privileges_required": ["HIGH", "LOW", "NONE", None],
    "cvss_version": ["2.0", "3.0", "3.1", "4.0", None],
}


@dataclass
class FeatureSchema:
    feature_names: list[str]
    numeric: list[str]
    encoded: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "feature_names": self.feature_names,
            "numeric": self.numeric,
            "encoded": self.encoded,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FeatureSchema":
        return cls(
            feature_names=list(data["feature_names"]),
            numeric=list(data["numeric"]),
            encoded=list(data["encoded"]),
        )


def _one_hot(series: pd.Series, vocab: list[Any]) -> pd.DataFrame:
    """Deterministic one-hot with explicit vocab including a missing-value slot."""
    out = pd.DataFrame(index=series.index)
    for v in vocab:
        name = f"{series.name}_{v if v is not None else 'missing'}"
        out[name] = (series == v).astype(np.float32)
    # Handle values not present in the vocabulary
    unknown = ~series.isin(vocab) & series.notna()
    if unknown.any():
        out[f"{series.name}_other"] = unknown.astype(np.float32)
    return out


def build_features(df: pd.DataFrame, schema: FeatureSchema | None = None) -> tuple[pd.DataFrame, FeatureSchema]:
    """Build the feature matrix; returns (X, schema).

    If schema is given, categorical columns are encoded to exactly match it
    (train / inference schema coherence).
    """
    numeric = df[NUMERIC_FEATURES].copy()
    for col in NUMERIC_FEATURES:
        numeric[col] = pd.to_numeric(numeric[col], errors="coerce").fillna(0.0).astype(np.float32)

    encoded_frames = []
    for col, vocab in CATEGORICAL_FEATURES.items():
        encoded_frames.append(_one_hot(df[col], vocab))
    encoded = pd.concat(encoded_frames, axis=1) if encoded_frames else pd.DataFrame(index=df.index)

    X = pd.concat([numeric, encoded], axis=1)

    if schema is None:
        schema = FeatureSchema(
            feature_names=list(X.columns), numeric=NUMERIC_FEATURES, encoded=list(encoded.columns)
        )
    else:
        # Reindex to the schema's feature list; missing columns (e.g. new toy vocab)
        # are filled with 0, extras are dropped.
        X = X.reindex(columns=schema.feature_names, fill_value=0.0)
    return X, schema
