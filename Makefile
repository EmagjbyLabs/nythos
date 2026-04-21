.PHONY: help check fmt test clippy run

CARGO ?= cargo

help:
	@printf '%s\n' 'Targets: check fmt test clippy run'

check:
	$(CARGO) check --all-targets

test:
	$(CARGO) test --all-targets

fmt:
	$(CARGO) fmt --check

clippy:
	$(CARGO) clippy --all-targets --all-features -- -D warnings

run:
	$(CARGO) run
