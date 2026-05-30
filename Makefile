.PHONY: test coverage coverage-summary coverage-check fmt

BASELINE ?= 86.0

test:
	cargo test --all
	cargo clippy --all-targets --all-features -- -D warnings

coverage:
	cargo llvm-cov --no-cfg-coverage --lcov --output-path lcov.info

coverage-summary:
	python3 coverage.py 1 $(BASELINE)

coverage-check: coverage
	python3 coverage.py 0 $(BASELINE)

fmt:
    cargo fmt --all