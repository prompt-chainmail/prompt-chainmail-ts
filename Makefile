# Prompt Chainmail TypeScript library.
# Run `make` or `make help` to list targets.

.DEFAULT_GOAL := help

.PHONY: help \
	install build test test-ci \
	benchmark benchmark-ci benchmark-baseline benchmark-baseline-ci \
	lint format security \
	fetch-classifier


help: ## Show this menu
	@awk 'BEGIN {FS = ":.*## "; printf "\nTargets:\n"} \
		/^[a-zA-Z0-9_.-]+:.*## / {printf "  %-22s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@printf "\n"

install: ## npm install
	npm install

build: ## Build dist/ + types
	npm run build

test: ## Vitest
	npm test

test-ci: ## Vitest (CI; same suite as test)
	npm run test:ci

benchmark: ## Vitest bench (local; no baseline gate)
	npm run benchmark

benchmark-ci: ## Vitest bench + compare against committed baseline
	npm run benchmark:ci

benchmark-baseline: ## Rewrite baseline stamped as runner=local
	npm run benchmark:baseline

benchmark-baseline-ci: ## Rewrite baseline stamped as runner=ubuntu-latest (CI)
	npm run benchmark:baseline:ci

lint: ## ESLint src/
	npm run lint


format: ## Prettier write
	npm run format

security: ## Semgrep on src/
	npm run security

fetch-classifier: ## Fetch pinned model_version from prompt-chainmail-models into src/
	npm run fetch:classifier
