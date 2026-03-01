.PHONY: help build test test-cov shell list lint lab lab-scan lab-report lab-probe lab-down scan clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

# ===== Build & Test =====

build: ## Build the Docker image
	docker compose build test

test: ## Run all 114 tests in Docker
	docker compose run --rm test

test-cov: ## Run tests with coverage report
	docker compose run --rm test-coverage

lint: ## Run linters (ruff + mypy)
	docker compose run --rm --entrypoint "" test sh -c "ruff check otscan/ && mypy otscan/ --ignore-missing-imports"

shell: ## Open interactive shell in container
	docker compose run --rm shell

list: ## List all 13 supported protocols
	docker compose run --rm list-protocols

# ===== Simulated OT Lab =====

lab: ## Start the full OT lab (14 simulated services)
	docker compose up ot-lab -d
	@echo ""
	@echo "OT Lab is starting..."
	@echo "  IP: 172.25.0.10"
	@echo "  Services: Modbus, S7comm, OPC UA, EtherNet/IP, DNP3, BACnet,"
	@echo "            IEC 104, FINS, MQTT, FTP, Telnet, HTTP HMI, VNC, SNMP"
	@echo ""
	@echo "  Run:  make lab-scan    (scan the lab)"
	@echo "        make lab-report  (scan + save JSON report)"
	@echo "        make lab-down    (stop the lab)"

lab-scan: ## Scan the simulated OT lab (all protocols + cred checks)
	docker compose run --rm scan-lab

lab-report: ## Scan lab and save JSON report to ./reports/
	@mkdir -p reports
	docker compose run --rm scan-lab-report
	@echo ""
	@echo "Report saved to: ./reports/otscan_lab_report.json"

lab-probe: ## Probe a single protocol (usage: make lab-probe PORT=502 PROTO="Modbus TCP")
	docker compose run --rm probe-lab $(PORT) '$(PROTO)'

lab-down: ## Stop the OT lab
	docker compose down

# ===== Scan real targets =====

scan: ## Scan a real target (usage: make scan TARGET=192.168.1.0/24 MODE=safe)
	docker compose run --rm scan

clean: ## Remove all Docker containers, images, and volumes
	docker compose down --rmi local --volumes --remove-orphans
