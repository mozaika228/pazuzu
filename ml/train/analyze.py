"""Analytics for inference output and feature drift.

Input files:
- predictions JSONL with fields: score, anomaly, latency_us, optional label
- baseline JSON from train.py (`feature_baseline.json`)
- optional current features CSV with columns matching baseline keys
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--predictions", type=str, required=True)
    parser.add_argument("--baseline", type=str, required=True)
    parser.add_argument("--current-features", type=str, default="")
    parser.add_argument("--out", type=str, default="artifacts/analytics_report.json")
    return parser.parse_args()


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def summarize_predictions(rows: list[dict]) -> dict:
    scores = np.array([float(r.get("score", 0.0)) for r in rows], dtype=np.float64)
    anomalies = np.array([bool(r.get("anomaly", False)) for r in rows], dtype=np.bool_)
    lat = np.array([float(r.get("latency_us", 0.0)) for r in rows], dtype=np.float64)

    summary = {
        "count": int(len(rows)),
        "anomaly_rate": float(np.mean(anomalies)) if len(rows) else 0.0,
        "score_p50": float(np.percentile(scores, 50)) if len(rows) else 0.0,
        "score_p95": float(np.percentile(scores, 95)) if len(rows) else 0.0,
        "latency_us_p50": float(np.percentile(lat, 50)) if len(rows) else 0.0,
        "latency_us_p95": float(np.percentile(lat, 95)) if len(rows) else 0.0,
    }

    labeled = [r for r in rows if "label" in r]
    if labeled:
        y_true = np.array([int(r["label"]) for r in labeled], dtype=np.int64)
        y_pred = np.array([1 if bool(r.get("anomaly", False)) else 0 for r in labeled], dtype=np.int64)
        tp = int(np.sum((y_true == 1) & (y_pred == 1)))
        fp = int(np.sum((y_true == 0) & (y_pred == 1)))
        fn = int(np.sum((y_true == 1) & (y_pred == 0)))
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        summary["labeled"] = {
            "count": int(len(labeled)),
            "precision": precision,
            "recall": recall,
            "tp": tp,
            "fp": fp,
            "fn": fn,
        }
    return summary


def drift_from_csv(baseline: dict, csv_path: Path) -> dict:
    import pandas as pd

    df = pd.read_csv(csv_path)
    report = {}
    for feature, stats in baseline.items():
        if feature not in df.columns:
            continue
        current_mean = float(df[feature].mean())
        base_mean = float(stats.get("mean", 0.0))
        base_std = float(stats.get("std", 0.0))
        z = (current_mean - base_mean) / (base_std + 1e-6)
        report[feature] = {
            "baseline_mean": base_mean,
            "current_mean": current_mean,
            "drift_zscore": float(z),
        }
    return report


def main() -> None:
    args = parse_args()
    rows = load_jsonl(Path(args.predictions))
    baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))

    out = {"prediction_summary": summarize_predictions(rows)}
    if args.current_features:
        out["feature_drift"] = drift_from_csv(baseline, Path(args.current_features))

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"wrote analytics report to {out_path}")


if __name__ == "__main__":
    main()
