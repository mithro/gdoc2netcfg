VENV := .venv
VENV_BIN := $(VENV)/bin
OUTPUT_DIR := out

# uv builds/syncs the venv. Resolve it to an absolute path: root's
# non-interactive PATH frequently omits uv's install dir (/usr/local/bin,
# ~/.local/bin), which would otherwise break `sudo make deploy` with
# "uv: No such file or directory". Falls back to bare `uv`; override with
# `make UV=/path/to/uv`.
UV ?= $(firstword $(shell command -v uv) $(wildcard /usr/local/bin/uv) $(wildcard $(HOME)/.local/bin/uv) uv)

# Create venv and install project with dev dependencies.
# Re-runs when pyproject.toml or uv.lock change.
$(VENV)/.stamp: pyproject.toml uv.lock
	$(UV) sync --dev
	touch $@

.PHONY: help
help: $(VENV)/.stamp ## Show this help message
	@grep -E '^[a-zA-Z_.-]+:.*##' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'
	@echo ""
	@$(VENV_BIN)/gdoc2netcfg --help

.PHONY: setup
setup: $(VENV)/.stamp ## Create local development virtualenv

.PHONY: run
run: $(VENV)/.stamp ## Run gdoc2netcfg (use ARGS= for subcommands)
	$(VENV_BIN)/gdoc2netcfg $(ARGS)

.PHONY: generate
generate: $(VENV)/.stamp fetch ## Generate configs into out/ (use ARGS= for specific generators)
	rm -rf $(OUTPUT_DIR)
	$(VENV_BIN)/gdoc2netcfg generate --output-dir $(OUTPUT_DIR) $(ARGS)

.PHONY: fetch
fetch: $(VENV)/.stamp ## Download CSVs from Google Sheets
	$(VENV_BIN)/gdoc2netcfg fetch

.PHONY: reachability
reachability: $(VENV)/.stamp ## Ping all hosts and report which are up/down
	$(VENV_BIN)/gdoc2netcfg reachability $(ARGS)

.PHONY: scan
scan: $(VENV)/.stamp ## Run reachability check then all network scans
	@echo "=== reachability ==="
	$(VENV_BIN)/gdoc2netcfg reachability
	@echo ""
	@echo "=== sshfp ==="
	$(VENV_BIN)/gdoc2netcfg sshfp
	@echo ""
	@echo "=== ssl-certs ==="
	$(VENV_BIN)/gdoc2netcfg ssl-certs
	@echo ""
	@echo "=== snmp ==="
	$(VENV_BIN)/gdoc2netcfg snmp
	@echo ""
	@echo "=== bmc-firmware ==="
	$(VENV_BIN)/gdoc2netcfg bmc-firmware
	@echo ""
	@echo "=== bridge ==="
	$(VENV_BIN)/gdoc2netcfg bridge

.PHONY: test
test: $(VENV)/.stamp ## Run tests
	$(VENV_BIN)/pytest

.PHONY: lint
lint: $(VENV)/.stamp ## Run linter
	$(VENV_BIN)/ruff check src/ tests/

INSTALL_DIR := /opt/gdoc2netcfg
DNSMASQ_CONF_DIR := /etc/dnsmasq.d

# gdoc2netcfg version that produced the deployed /etc state (for etckeeper commits)
GDOC2NETCFG_VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo unknown)
# Path-scoped etckeeper commit of a deploy. Usage: $(ETCKEEPER_COMMIT) "<msg>" <path>
ETCKEEPER_COMMIT := $(VENV_BIN)/python scripts/etckeeper_commit.py --message

.PHONY: deploy-dnsmasq-internal
deploy-dnsmasq-internal: generate ## Generate and deploy internal dnsmasq configs (run with sudo)
	rm $(DNSMASQ_CONF_DIR)/internal/generated/*.conf
	cp $(OUTPUT_DIR)/internal/*.conf $(DNSMASQ_CONF_DIR)/internal/generated/
	systemctl restart dnsmasq@internal
	$(ETCKEEPER_COMMIT) "gdoc2netcfg deploy dnsmasq-internal: $(GDOC2NETCFG_VERSION)" $(DNSMASQ_CONF_DIR)/internal/generated

.PHONY: deploy-dnsmasq-external
deploy-dnsmasq-external: generate ## Generate and deploy external dnsmasq configs (run with sudo)
	rm $(DNSMASQ_CONF_DIR)/external/generated/*.conf
	cp $(OUTPUT_DIR)/external/*.conf $(DNSMASQ_CONF_DIR)/external/generated/
	systemctl restart dnsmasq@external
	$(ETCKEEPER_COMMIT) "gdoc2netcfg deploy dnsmasq-external: $(GDOC2NETCFG_VERSION)" $(DNSMASQ_CONF_DIR)/external/generated

.PHONY: deploy-dnsmasq
deploy-dnsmasq: deploy-dnsmasq-internal deploy-dnsmasq-external ## Deploy both internal and external dnsmasq configs (run with sudo)

NGINX_CONF_DIR := /etc/nginx
NGINX_GEN_DIR := $(NGINX_CONF_DIR)/gdoc2netcfg

.PHONY: deploy-nginx
deploy-nginx: generate ## Generate and deploy nginx configs (run with sudo)
	rm -rf $(NGINX_GEN_DIR)/sites-available $(NGINX_GEN_DIR)/scripts $(NGINX_GEN_DIR)/conf.d $(NGINX_GEN_DIR)/stream.d
	mkdir -p $(NGINX_GEN_DIR)
	cp -r $(OUTPUT_DIR)/nginx/* $(NGINX_GEN_DIR)/
	touch $(NGINX_GEN_DIR)/status.txt && chown www-data:www-data $(NGINX_GEN_DIR)/status.txt
	nginx -t
	systemctl reload nginx
	$(ETCKEEPER_COMMIT) "gdoc2netcfg deploy nginx: $(GDOC2NETCFG_VERSION)" $(NGINX_GEN_DIR)

SSH_KNOWN_HOSTS := /etc/ssh/ssh_known_hosts

.PHONY: deploy-known-hosts
deploy-known-hosts: generate ## Generate and deploy system-wide SSH known_hosts (run with sudo)
	cp $(OUTPUT_DIR)/known_hosts $(SSH_KNOWN_HOSTS)
	$(ETCKEEPER_COMMIT) "gdoc2netcfg deploy known-hosts: $(GDOC2NETCFG_VERSION)" $(SSH_KNOWN_HOSTS)

.PHONY: deploy
deploy: deploy-dnsmasq deploy-nginx deploy-known-hosts ## Run all deploy steps (run with sudo)

.PHONY: install
install: ## Install into /opt/gdoc2netcfg
	$(UV) venv $(INSTALL_DIR)
	$(UV) pip install --python $(INSTALL_DIR)/bin/python .

.PHONY: clean
clean: ## Remove generated output
	rm -rf $(OUTPUT_DIR)

.PHONY: dist-clean
dist-clean: clean ## Remove generated output and virtualenv
	rm -rf $(VENV)
