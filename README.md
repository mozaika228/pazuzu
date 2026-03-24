# Pazuzu

High-performance WAF / IPS / Rate Limiter / Bot Protection built on eBPF/XDP with a userspace control plane.

## In This Repo
- `ebpf/xdp_pass.bpf.c` - XDP program: IPv4 parsing, IP blocklist, CIDR blocklist (LPM trie), TCP signature detection (NULL/XMAS), rate limiting, counters, rule epoch.
- `crates/loader` - userspace loader + HTTP API (axum) for rules and rate control.
- `crates/ml_infer` - Rust inference module with thresholding and rolling analytics.
- `ml/train` - Python training and analytics pipeline (`train.py`, `analyze.py`).

## Quick Start (Linux)

Dependencies:
- `clang`, `llvm`, `bpftool`
- `libbpf` (dev)
- `rustup` (Rust 1.76+)
- kernel headers

Build and run:
```bash
cd pazuzu
cargo build -p pazuzu-loader
sudo ./target/debug/pazuzu-loader --iface eth0 --mode native --api 127.0.0.1:8080 --rate 1000 --burst 2000 --pin-maps /sys/fs/bpf/pazuzu --api-key pazuzu-dev-key
```

Stop: `Ctrl+C`.

## API

- All endpoints except `/health` require header: `X-API-Key: <your-key>` when `--api-key` is set.
- `POST /block/{ip}` - add IP to blocklist
- `DELETE /block/{ip}` - remove IP from blocklist
- `POST /block-cidr` - JSON `{ "cidr": "10.0.0.0/8" }`
- `DELETE /block-cidr` - JSON `{ "cidr": "10.0.0.0/8" }`
- `GET /signatures/tcp` - current TCP signature rules
- `POST /signatures/tcp` - JSON `{ "block_null_scan": true, "block_xmas_scan": true }`
- `GET /rules/config` - current control-plane rules snapshot
- `POST /rules/batch` - apply batch rule changes and bump epoch once
- `GET /metrics` - Prometheus metrics for control-plane and eBPF counters
- `POST /rate` - JSON `{ "rate_per_sec": 1000, "burst": 2000 }`
- `GET /stats` - counters
- `GET /rules/epoch` - current rules epoch
- `POST /rules/epoch` - bump rules epoch

## Notes

- `libbpf-cargo` generates the skeleton from `ebpf/xdp_pass.bpf.c` during `cargo build`.
- If native XDP fails, try `--mode skb`.
- Use `--pin-maps /sys/fs/bpf/pazuzu` to persist maps and reload programs without losing rules.
- Batch limits: up to `2048` IP updates and `2048` CIDR updates per `/rules/batch` call.

## Next

Kernel plan:
- signature detection
- conntrack + SYN proxy

ML plan:
- offline training (Python)
- on-device inference (Rust, ONNX/TinyML)
- behavioral model and bot detection

## ML And Analytics Quickstart

```bash
cd pazuzu/ml/train
python train.py --out artifacts
python validate_artifacts.py --artifacts artifacts --min-auc 0.75 --min-f1 0.55
python analyze.py --predictions /path/to/predictions.jsonl --baseline artifacts/feature_baseline.json --out artifacts/analytics_report.json
```

## Tests And Validation

```bash
cd pazuzu
cargo test -p pazuzu-ml-infer
cargo test -p pazuzu-loader
```

## DevEx And Quality

- Standardized local commands: `Makefile`
- CI pipeline: `.github/workflows/ci.yml`
- Contributor guide: `CONTRIBUTING.md`
- Editor consistency: `.editorconfig`

Run full local quality gate:

```bash
cd pazuzu
make qa
```
