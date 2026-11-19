.PHONY: test lint build-agent build-server up down

test:
	go test ./...

lint:
	golangci-lint run ./...

build-agent:
	go build -o bin/fleetguard-agent ./cmd/agent

build-server:
	go build -o bin/fleetguard-server ./cmd/server

up:
	docker compose -f deploy/docker-compose.yml up -d --build

down:
	docker compose -f deploy/docker-compose.yml down
