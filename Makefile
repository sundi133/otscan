.PHONY: help build test test-cov shell scan list lint sim clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build the Docker image
	docker compose build test

test: ## Run all tests in Docker
	docker compose run --rm test

test-cov: ## Run tests with coverage report
	docker compose run --rm test-coverage

shell: ## Open interactive shell in container
	docker compose run --rm shell

list: ## List supported protocols
	docker compose run --rm list-protocols

scan: ## Scan a target (usage: make scan TARGET=192.168.1.0/24 MODE=safe)
	docker compose run --rm scan

sim: ## Start Modbus simulator + scan it
	docker compose up modbus-sim -d
	@echo "Waiting for simulator to start..."
	@sleep 5
	docker compose run --rm scan-sim
	docker compose down modbus-sim

lint: ## Run linters (ruff + mypy)
	docker compose run --rm --entrypoint "" test sh -c "ruff check otscan/ && mypy otscan/ --ignore-missing-imports"

clean: ## Remove Docker containers and images
	docker compose down --rmi local --volumes --remove-orphans
