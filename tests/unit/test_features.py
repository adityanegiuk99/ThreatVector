"""Unit tests for feature building and schema coherence."""
from __future__ import annotations

import pandas as pd

from app.services.ml.features import NUMERIC_FEATURES, build_features


def make_df(n=5):
    return pd.DataFrame(
        {
            "cvss_base_score": [7.5] * n,
            "exploitability_score": [3.9] * n,
            "impact_score": [5.9] * n,
            "n_cwe": [1] * n,
            "n_references": [4] * n,
            "n_affected_products": [2] * n,
            "desc_len": [500] * n,
            "has_cwe": [1.0] * n,
            "scope_changed": [0.0] * n,
            "attack_vector": ["NETWORK"] * (n - 1) + [None],
            "attack_complexity": ["LOW"] * n,
            "user_interaction": ["NONE"] * n,
            "privileges_required": ["NONE"] * n,
            "cvss_version": ["3.1"] * n,
        }
    )


def test_schema_stable_between_calls():
    X1, s1 = build_features(make_df())
    X2, s2 = build_features(make_df())
    assert list(X1.columns) == list(X2.columns) == s1.feature_names


def test_unknown_category_maps_to_other():
    df = make_df(3)
    df.loc[0, "attack_vector"] = "SOMETHING_NEW"
    X, schema = build_features(df)
    assert X.iloc[0]["attack_vector_other"] == 1.0


def test_null_numeric_filled_zero():
    df = make_df(2)
    df.loc[0, "cvss_base_score"] = None
    X, _ = build_features(df)
    assert X.iloc[0]["cvss_base_score"] == 0.0


def test_all_numeric_features_present():
    X, _ = build_features(make_df())
    for f in NUMERIC_FEATURES:
        assert f in X.columns
