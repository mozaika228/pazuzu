# Pazuzu

High-performance WAF / IPS / Rate Limiter / Bot Protection built on eBPF/XDP with a userspace control plane.

## In This Repo
- `ebpf/xdp_pass.bpf.c` — XDP program: IPv4 parsing, blocklist, rate limiting, counters, rule epoch.
- `crates/loader` — userspace loader + HTTP API (axum) for rules and rate control.
- `crates/ml_infer` — Rust inference stub.
- `ml/train` — Python training skeleton.

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
sudo ./target/debug/pazuzu-loader --iface eth0 --mode native --api 127.0.0.1:8080 --rate 1000 --burst 2000 --pin-maps /sys/fs/bpf/pazuzu
```

Stop: `Ctrl+C`.

## API

- `POST /block/{ip}` — add IP to blocklist
- `DELETE /block/{ip}` — remove IP from blocklist
- `POST /rate` — JSON `{ "rate_per_sec": 1000, "burst": 2000 }`
- `GET /stats` — counters
- `GET /rules/epoch` — current rules epoch
- `POST /rules/epoch` — bump rules epoch

## Notes

- `libbpf-cargo` generates the skeleton from `ebpf/xdp_pass.bpf.c` during `cargo build`.
- If native XDP fails, try `--mode skb`.
- Use `--pin-maps /sys/fs/bpf/pazuzu` to persist maps and reload programs without losing rules.

## Next

Kernel plan:
- signature detection
- conntrack + SYN proxy

ML plan:
- offline training (Python)
- on-device inference (Rust, ONNX/TinyML)
- behavioral model and bot detection
