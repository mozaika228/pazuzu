"""Validate ML training artifacts before deployment."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


REQUIRED_FEATURES = {"pkt_rate", "syn_rate", "ua_entropy", "req_burst"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", type=str, default="artifacts")
    parser.add_argument("--min-auc", type=float, default=0.75)
    parser.add_argument("--min-f1", type=float, default=0.55)
    return parser.parse_args()


def read_json(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"missing artifact: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    args = parse_args()
    root = Path(args.artifacts)

    meta = read_json(root / "model_meta.json")
    report = read_json(root / "eval_report.json")
    baseline = read_json(root / "feature_baseline.json")

    features = set(meta.get("features", []))
    if features != REQUIRED_FEATURES:
        raise ValueError(f"unexpected feature set: {features}")

    threshold = float(meta.get("decision_threshold", -1))
    if threshold < 0.0 or threshold > 1.0:
        raise ValueError(f"invalid decision_threshold: {threshold}")

    auc = float(report.get("roc_auc", -1))
    f1 = float(report.get("f1_1", -1))
    if auc < args.min_auc:
        raise ValueError(f"roc_auc below threshold: {auc} < {args.min_auc}")
    if f1 < args.min_f1:
        raise ValueError(f"f1_1 below threshold: {f1} < {args.min_f1}")

    missing_baseline = REQUIRED_FEATURES - set(baseline.keys())
    if missing_baseline:
        raise ValueError(f"missing baseline features: {missing_baseline}")

    print("artifacts validation passed")


if __name__ == "__main__":
    main()
