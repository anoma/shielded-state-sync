ALL_FEATURES := serde,random-flag-ciphertexts

.PHONY: all
all: clippy-no-std-all-features

.PHONY: clippy-no-std-all-features
clippy-no-std-all-features:
	cargo clippy --features $(ALL_FEATURES) -- -D warnings

.PHONY: clippy-no-std
clippy-no-std:
	cargo clippy -- -D warnings

.PHONY: clippy-all
clippy-all:
	cargo clippy --features $(ALL_FEATURES) --all-targets --tests -- -D warnings

.PHONY: docs
docs:
	cargo doc

.PHONY: fmt
fmt:
	cargo fmt

.PHONY: fmt-check
fmt-check:
	cargo fmt --check

.PHONY: test
test:
	cargo test

.PHONY: bench
bench:
	cargo bench
