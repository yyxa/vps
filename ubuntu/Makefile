SHELL := /bin/bash
RAW   := https://raw.githubusercontent.com/yyxa/vps/main/ubuntu/setup.sh

lint:            ## shellcheck + синтаксис
	shellcheck -S warning -x setup.sh
	bash -n setup.sh

fmt:             ## форматирование
	shfmt -w -i 2 -ci setup.sh

dry:             ## план без изменений
	sudo bash setup.sh --dry-run --yes --user $${SUDO_USER:-ubuntu}

url:             ## показать одно-liner
	@echo "curl -fsSL $(RAW) | sudo bash"

help:
	@grep -E '^[a-z-]+:.*?##' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  %-6s %s\n", $$1, $$2}'