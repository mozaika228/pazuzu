# Contributing

## Local Setup

1. Install Rust toolchain (`rustup`) and Python 3.12+.
2. Install Python dependencies:
   - `python -m pip install -r ml/train/requirements.txt`

## Quality Gates

Before opening a PR, run:

```bash
make qa
```

If your environment does not have `make`, run commands manually:

```bash
python -m py_compile ml/train/train.py ml/train/analyze.py ml/train/validate_artifacts.py
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Commit Guidance

- Keep commits focused and atomic.
- Include tests for behavior changes.
- Update docs when endpoint or CLI behavior changes.
