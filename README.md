# Pazuzu

Высокопроизводительный WAF / IPS / Rate Limiter / Bot Protection на базе eBPF/XDP + userspace control plane.

Сейчас в репозитории:
- `ebpf/xdp_pass.bpf.c` — минимальная XDP программа (XDP_PASS).
- `crates/loader` — userspace loader на Rust + libbpf-rs (с автогенерацией skeleton).

## Быстрый старт (Linux)

Зависимости:
- `clang`, `llvm`, `bpftool`
- `libbpf` (dev)
- `rustup` (Rust 1.76+)
- заголовки ядра

Сборка и запуск:
```bash
cd pazuzu
cargo build -p pazuzu-loader
sudo ./target/debug/pazuzu-loader --iface eth0 --mode native
```

Остановка: `Ctrl+C`.

Примечания:
- `libbpf-cargo` генерирует skeleton из `ebpf/xdp_pass.bpf.c` во время `cargo build`.
- Если загрузка XDP в native режиме не проходит, попробуйте `--mode skb`.

## Дальше

План для ядра:
- rate limiting (token bucket / sliding window)
- signature detection
- conntrack + SYN proxy

План для ML:
- offline training (Python)
- on-device inference (Rust, ONNX/TinyML)
- поведенческая модель и bot detection
