.PHONY: all build test lint tidy docker-agent docker-registry

AGENT_IMAGE ?= kube-oidc-fed-broker:latest
REGISTRY_IMAGE ?= kube-oidc-fed-registry:latest

all: build

build:
	go build ./...

test:
	go test ./... -v -count=1

lint:
	golangci-lint run ./...

tidy:
	go mod tidy

docker-agent:
	docker build -f Dockerfile.agent -t $(AGENT_IMAGE) .

docker-registry:
	docker build -f Dockerfile.registry -t $(REGISTRY_IMAGE) .

docker: docker-agent docker-registry

local-up:
	cd local-test && docker-compose up -d

local-down:
	cd local-test && docker-compose down

local-test: local-up
	sleep 5
	cd local-test && ./setup-minio.sh && ./test-flow.sh
