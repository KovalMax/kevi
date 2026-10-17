SHELL := /bin/bash

.PHONY: test fmt clippy check coverage coverage-summary coverage-check

BASELINE ?= 86.0

test:
	KEVI_INSECURE_CACHE_FALLBACK=1 cargo test --workspace

fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

check: test fmt clippy

coverage:
	cargo llvm-cov --workspace --no-cfg-coverage --lcov --output-path lcov.info

coverage-summary:
	python3 coverage.py 1 $(BASELINE)

coverage-check: coverage
	python3 coverage.py 0 $(BASELINE)
