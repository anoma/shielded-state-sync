.PHONY: all
all: clippy-no-std-all-features

.PHONY: clippy-no-std-all-features
clippy-no-std-all-features:
	cargo clippy --features serde -- -D warnings

.PHONY: clippy-no-std
clippy-no-std:
	cargo clippy -- -D warnings

.PHONY: clippy-all
clippy-all:
	cargo clippy --features serde --all-targets --tests -- -D warnings

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
