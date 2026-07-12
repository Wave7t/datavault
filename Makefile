.PHONY: all build proto generate-check fmt fmt-check vet test test-race tidy-check ci clean install

BINARIES := dvault datavault-agent datavault-server
CMDS := cmd/dvault cmd/datavault-agent cmd/datavault-server
DIST_DIR := dist
GO_FILES := $(shell find . -type f -name '*.go' -not -path './.git/*' -not -path './vendor/*')

all: build

build: proto
	mkdir -p $(DIST_DIR)
	for cmd in $(CMDS); do \
		go build -o $(DIST_DIR)/$$(basename $$cmd) ./$$cmd; \
	done

proto:
	buf generate

generate-check: proto
	git diff --exit-code -- pkg/agentpb pkg/backuppb

fmt:
	gofmt -w $(GO_FILES)

fmt-check:
	test -z "$$(gofmt -l $(GO_FILES))"

vet:
	go vet ./...

test:
	go test ./... -count=1

test-race:
	go test -race ./... -count=1

tidy-check:
	go mod tidy -diff

ci: fmt-check tidy-check generate-check vet test-race build

clean:
	rm -rf $(DIST_DIR)/

install: build
	install -m 755 $(DIST_DIR)/dvault /usr/bin/dvault
	install -m 755 $(DIST_DIR)/datavault-agent /usr/bin/datavault-agent
	install -m 755 $(DIST_DIR)/datavault-server /usr/bin/datavault-server
	install -m 644 scripts/datavault-agent.service /etc/systemd/system/
	install -m 644 scripts/datavault-server.service /etc/systemd/system/
	systemctl daemon-reload
