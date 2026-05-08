VERSION ?= dev
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
BUILD_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GO_VERSION := $(shell go version | awk '{print $$3}')

LDFLAGS := -X vulnscan-backend/boot.ProductVersion=$(VERSION) \
           -X vulnscan-backend/boot.BuildTime=$(BUILD_TIME) \
           -X vulnscan-backend/boot.BuildCommit=$(BUILD_COMMIT) \
           -X vulnscan-backend/boot.GoVersion=$(GO_VERSION)

.PHONY: build wire run clean tidy

build:
	go build -ldflags "$(LDFLAGS)" -o vulnscan-server ./cmd/server

wire:
	cd di && wire

run:
	go run -ldflags "$(LDFLAGS)" ./cmd/server

tidy:
	go mod tidy

clean:
	rm -f vulnscan-server
