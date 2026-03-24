.PHONY: help py-install py-check ml-train ml-validate rust-fmt rust-clippy rust-test qa

help:
	@echo "Targets:"
	@echo "  py-install   Install Python dependencies"
	@echo "  py-check     Validate Python scripts syntax"
	@echo "  ml-train     Run ML training (synthetic)"
	@echo "  ml-validate  Validate ML artifacts"
	@echo "  rust-fmt     Check Rust formatting"
	@echo "  rust-clippy  Run Rust clippy checks"
	@echo "  rust-test    Run Rust tests"
	@echo "  qa           Run all available quality checks"

py-install:
	python -m pip install -r ml/train/requirements.txt

py-check:
	python -m py_compile ml/train/train.py ml/train/analyze.py ml/train/validate_artifacts.py

ml-train:
	python ml/train/train.py --out ml/train/artifacts

ml-validate:
	python ml/train/validate_artifacts.py --artifacts ml/train/artifacts --min-auc 0.75 --min-f1 0.55

rust-fmt:
	cargo fmt --all -- --check

rust-clippy:
	cargo clippy --workspace --all-targets -- -D warnings

rust-test:
	cargo test --workspace

qa: py-check rust-fmt rust-clippy rust-test
