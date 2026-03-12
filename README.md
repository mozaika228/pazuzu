# Pazuzu

¬ысокопроизводительный WAF / IPS / Rate Limiter / Bot Protection на базе eBPF/XDP + userspace control plane.

—ейчас в репозитории:
- `ebpf/xdp_pass.bpf.c` Ч XDP программа: парсинг IPv4, blocklist, rate limiting, counters.
- `crates/loader` Ч userspace loader + HTTP API (axum) дл€ управлени€ правилами и rate limit.
- `crates/ml_infer` Ч каркас inference на Rust.
- `ml/train` Ч каркас обучени€ в Python.

## Ѕыстрый старт (Linux)

«ависимости:
- `clang`, `llvm`, `bpftool`
- `libbpf` (dev)
- `rustup` (Rust 1.76+)
- заголовки €дра

—борка и запуск:
```bash
cd pazuzu
cargo build -p pazuzu-loader
sudo ./target/debug/pazuzu-loader --iface eth0 --mode native --api 127.0.0.1:8080 --rate 1000 --burst 2000
```

ќстановка: `Ctrl+C`.

## API

- `POST /block/{ip}` Ч добавить IP в blocklist
- `DELETE /block/{ip}` Ч удалить IP из blocklist
- `POST /rate` Ч JSON `{ "rate_per_sec": 1000, "burst": 2000 }`
- `GET /stats` Ч counters

## ѕримечани€

- `libbpf-cargo` генерирует skeleton из `ebpf/xdp_pass.bpf.c` во врем€ `cargo build`.
- ≈сли загрузка XDP в native режиме не проходит, попробуйте `--mode skb`.

## ƒальше

ѕлан дл€ €дра:
- signature detection
- conntrack + SYN proxy

ѕлан дл€ ML:
- offline training (Python)
- on-device inference (Rust, ONNX/TinyML)
- поведенческа€ модель и bot detection
