.PHONY: lint lint-fix fmt fmt-check

CLIPPY_ALLOW = -A clippy::wildcard-imports -A clippy::missing_errors_doc -A clippy::redundant_field_names -A clippy::doc_markdown -A clippy::tabs_in_doc_comments
CLIPPY_FLAGS = -W clippy::pedantic $(CLIPPY_ALLOW) -D warnings

lint:
	cargo clippy --all-targets --locked -- $(CLIPPY_FLAGS)

lint-fix:
	cargo clippy --all-targets --locked --fix -- $(CLIPPY_FLAGS)

fmt:
	cargo fmt

fmt-check:
	cargo fmt --check
