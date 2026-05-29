SHELL := /bin/bash

.PHONY: test fmt clippy check

test:
	cargo test --workspace

fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

check: test fmt clippy
