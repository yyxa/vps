SHELL := /bin/bash

.PHONY: monitoring-up
monitoring-up:
	@cd devops && \
	docker compose -f docker-compose.monitoring.yml up -d

.PHONY: monitoring-down
monitoring-down:
	@cd devops && \
	docker compose -f docker-compose.monitoring.yml down