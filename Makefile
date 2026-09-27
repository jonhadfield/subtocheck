SOURCE_FILES?=$$(go list ./...)
TEST_PATTERN?=.
TEST_OPTIONS?=-race -v

test:
	go test $(TEST_OPTIONS) -covermode=atomic -coverprofile=coverage.txt -run $(TEST_PATTERN) -timeout=30s $(SOURCE_FILES)

cover: test
	go tool cover -html=coverage.txt

fmt:
	gofmt -w -s $$(git ls-files '*.go')

lint:
	golangci-lint run ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

ci: lint test vuln

find-updates:
	go list -u -m -json all | go-mod-outdated -update -direct

BUILD_TAG := $(shell git describe --tags 2>/dev/null)
BUILD_SHA := $(shell git rev-parse --short HEAD)
BUILD_DATE := $(shell date -u '+%Y/%m/%d:%H:%M:%S')

build: fmt
	CGO_ENABLED=0 go build -ldflags '-s -w -X "main.version=[$(BUILD_TAG)-$(BUILD_SHA)] $(BUILD_DATE) UTC"' -o "dist/subtocheck" ./cmd/subtocheck

snapshot:
	goreleaser release --snapshot --clean -f goreleaser.yml

clean:
	rm -rf dist

install:
	go install ./cmd/...

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := build
