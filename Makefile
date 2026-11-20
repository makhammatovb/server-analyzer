.PHONY: test lint build-agent build-server dist web up down

test:
	go test ./...

lint:
	golangci-lint run ./...

build-agent:
	go build -o bin/fleetguard-agent ./cmd/agent

build-server:
	go build -o bin/fleetguard-server ./cmd/server

# dist builds what Caddy serves for the installer: the agent for each supported
# architecture with a SHA-256 checksum beside it.
VERSION ?= $(shell git describe --always --dirty 2>/dev/null || echo dev)
dist:
	@mkdir -p deploy/site/downloads
	@for arch in amd64 arm64; do \
	  n=fleetguard-agent-linux-$$arch; \
	  CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath \
	    -ldflags "-s -w -X github.com/makhammatovb/fleetguard/internal/agent.Version=$(VERSION)" \
	    -o deploy/site/downloads/$$n ./cmd/agent || exit 1; \
	  ( cd deploy/site/downloads && { sha256sum $$n 2>/dev/null || shasum -a 256 $$n; } > $$n.sha256 ); \
	done

web:
	cd web && npm ci && npm run build

up: dist web
	docker compose --env-file .env -f deploy/docker-compose.yml up -d --build

down:
	docker compose --env-file .env -f deploy/docker-compose.yml down
