SHELL := /bin/bash
GOCACHE ?= $(CURDIR)/.gocache
GOMODCACHE ?= $(CURDIR)/.gomodcache
export GOCACHE GOMODCACHE

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-s -w -X github.com/temren/cmd/temren/cmd.Version=$(VERSION)"

.PHONY: all build test lint vet tidy fmt cli api worker clean docker docker-multiarch \
        cover frontend frontend-build release security run dev

all: lint test build

# ---- Go ----

build: cli api worker

cli:
	go build $(LDFLAGS) -o bin/temren ./cmd/temren

api:
	go build $(LDFLAGS) -o bin/temren-api ./cmd/api

worker:
	go build $(LDFLAGS) -o bin/temren-worker ./cmd/worker

test:
	go test -race -timeout=180s ./...

cover:
	go test -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Open coverage.html"

vet:
	go vet ./...

fmt:
	gofmt -s -w .

tidy:
	go mod tidy

lint:
	@command -v golangci-lint >/dev/null || (echo ">> Install golangci-lint: https://golangci-lint.run/welcome/install/" && exit 1)
	golangci-lint run ./...

security:
	@command -v gosec >/dev/null || (echo ">> Install gosec: go install github.com/securego/gosec/v2/cmd/gosec@latest" && exit 1)
	gosec -quiet ./...

# ---- Frontend ----

frontend:
	cd frontend && npm install --prefer-offline --no-audit --no-fund

frontend-build:
	cd frontend && npm run build

# ---- Containers ----

docker:
	docker build -t temren:$(VERSION) -f Dockerfile .

docker-multiarch:
	docker buildx build --platform=linux/amd64,linux/arm64 -t temren:$(VERSION) -f Dockerfile --push .

# ---- Release ----

release: clean
	@mkdir -p dist
	for os in linux darwin windows; do \
	  for arch in amd64 arm64; do \
	    out=dist/temren-$$os-$$arch ; [ "$$os" = windows ] && out=$$out.exe ; \
	    echo ">> $$out" ; \
	    GOOS=$$os GOARCH=$$arch go build $(LDFLAGS) -o $$out ./cmd/temren ; \
	  done ; \
	done
	cd dist && for f in temren-*; do shasum -a 256 $$f > $$f.sha256; done

clean:
	rm -rf bin dist coverage.out coverage.html

# ---- Dev ----

dev:
	@command -v air >/dev/null || (echo ">> Install air: go install github.com/cosmtrek/air@latest"; exit 1)
	air

run: build
	./bin/temren-api
