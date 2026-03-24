# ML Pipeline

## Training (Python)

Run deterministic bootstrap training (synthetic data):

```bash
cd ml/train
python train.py --out artifacts
```

Train on your dataset CSV (must include `pkt_rate,syn_rate,ua_entropy,req_burst,label`):

```bash
python train.py --dataset /path/to/flows.csv --out artifacts
```

Artifacts:
- `model_meta.json` - model identity, threshold, feature list
- `eval_report.json` - ROC AUC and core classification metrics
- `feature_baseline.json` - baseline feature stats for drift checks

## Analytics (Python)

Summarize inference output and optional feature drift:

```bash
python analyze.py --predictions /path/to/predictions.jsonl --baseline artifacts/feature_baseline.json --out artifacts/analytics_report.json
```

`predictions.jsonl` schema per row:
- `score` (float)
- `anomaly` (bool)
- `latency_us` (float)
- optional `label` (0 or 1) for precision/recall

## Validation (Python)

Validate training artifacts before promoting model:

```bash
python validate_artifacts.py --artifacts artifacts --min-auc 0.75 --min-f1 0.55
```

## Inference (Rust)

`crates/ml_infer` now provides:
- model metadata loading (`model_meta.json`)
- low-latency heuristic scoring path
- anomaly decision by threshold
- rolling analytics (`InferenceStats` with EWMA risk)
