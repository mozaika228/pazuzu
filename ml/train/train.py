"""Offline training pipeline for Pazuzu behavioral detection.

This script is deterministic by default and can work in two modes:
1) Use `--dataset` CSV with expected feature columns and `label`.
2) Fallback to synthetic data for local bootstrap.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split


FEATURES = ["pkt_rate", "syn_rate", "ua_entropy", "req_burst"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=str, default="")
    parser.add_argument("--out", type=str, default="artifacts")
    parser.add_argument("--seed", type=int, default=42)
    return parser.parse_args()


def synthetic_dataset(seed: int) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    n = 6000
    pkt_rate = rng.gamma(shape=2.0, scale=120.0, size=n)
    syn_rate = rng.gamma(shape=1.7, scale=35.0, size=n)
    ua_entropy = rng.normal(loc=1.0, scale=0.45, size=n).clip(0.0, 3.5)
    req_burst = rng.gamma(shape=1.3, scale=9.0, size=n)
    x = np.column_stack([pkt_rate, syn_rate, ua_entropy, req_burst])

    # Synthetic ground truth with nonlinear interaction.
    signal = (
        0.011 * pkt_rate
        + 0.028 * syn_rate
        + 0.7 * ua_entropy
        + 0.06 * req_burst
        - 3.3
    )
    p = 1.0 / (1.0 + np.exp(-signal))
    y = (rng.random(n) < p).astype(np.int64)
    return x, y


def csv_dataset(path: Path) -> tuple[np.ndarray, np.ndarray]:
    import pandas as pd

    df = pd.read_csv(path)
    missing = [c for c in [*FEATURES, "label"] if c not in df.columns]
    if missing:
        raise ValueError(f"missing columns: {missing}")
    x = df[FEATURES].to_numpy(dtype=np.float32)
    y = df["label"].to_numpy(dtype=np.int64)
    return x, y


def feature_stats(x: np.ndarray) -> dict:
    stats = {}
    for i, name in enumerate(FEATURES):
        col = x[:, i]
        stats[name] = {
            "mean": float(np.mean(col)),
            "std": float(np.std(col)),
            "p50": float(np.percentile(col, 50)),
            "p95": float(np.percentile(col, 95)),
        }
    return stats


def main() -> None:
    args = parse_args()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.dataset:
        x, y = csv_dataset(Path(args.dataset))
        dataset_type = "csv"
    else:
        x, y = synthetic_dataset(args.seed)
        dataset_type = "synthetic"

    x_train, x_val, y_train, y_val = train_test_split(
        x, y, test_size=0.25, random_state=args.seed, stratify=y
    )

    model = GradientBoostingClassifier(random_state=args.seed)
    model.fit(x_train, y_train)
    prob = model.predict_proba(x_val)[:, 1]
    pred = (prob >= 0.5).astype(np.int64)

    auc = roc_auc_score(y_val, prob)
    report = classification_report(y_val, pred, output_dict=True, zero_division=0)

    meta = {
        "name": "pazuzu-behavior-model",
        "version": "0.2.0",
        "framework": "sklearn.GradientBoostingClassifier",
        "features": FEATURES,
        "decision_threshold": 0.5,
        "dataset": dataset_type,
        "export": "model.onnx",
    }

    eval_report = {
        "roc_auc": float(auc),
        "accuracy": float(report["accuracy"]),
        "precision_1": float(report["1"]["precision"]),
        "recall_1": float(report["1"]["recall"]),
        "f1_1": float(report["1"]["f1-score"]),
        "support_1": int(report["1"]["support"]),
    }

    (out_dir / "model_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    (out_dir / "eval_report.json").write_text(
        json.dumps(eval_report, indent=2), encoding="utf-8"
    )
    (out_dir / "feature_baseline.json").write_text(
        json.dumps(feature_stats(x_train), indent=2), encoding="utf-8"
    )

    print(f"wrote artifacts to {out_dir}")


if __name__ == "__main__":
    main()
