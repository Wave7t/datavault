.PHONY: all build release-linux-amd64 proto proto-format-check proto-lint generate-check fmt fmt-check vet test test-race tidy-check ci clean install

BINARIES := dvault datavault-agent datavault-server
CMDS := cmd/dvault cmd/datavault-agent cmd/datavault-server
DIST_DIR := dist
RELEASE_DIR := $(DIST_DIR)/release/linux-amd64
GO_FILES := $(shell find . -type f -name '*.go' -not -path './.git/*' -not -path './vendor/*')
PROTO_GENERATED_FILES := pkg/agentpb/v1/agent.pb.go pkg/agentpb/v1/agent_grpc.pb.go pkg/backuppb/v1/backup.pb.go pkg/backuppb/v1/backup_grpc.pb.go

all: build

build: proto
	mkdir -p $(DIST_DIR)
	for cmd in $(CMDS); do \
		go build -o $(DIST_DIR)/$$(basename $$cmd) ./$$cmd; \
	done

release-linux-amd64:
	./scripts/build-release-linux-amd64.sh $(RELEASE_DIR)

proto:
	buf generate

proto-format-check:
	test -z "$$(buf format -d)"

proto-lint:
	buf lint

generate-check: proto
	git diff --exit-code -- $(PROTO_GENERATED_FILES)

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

ci: fmt-check tidy-check proto-format-check proto-lint generate-check vet test-race build

clean:
	rm -rf $(DIST_DIR)/

install: build
	install -m 755 $(DIST_DIR)/dvault /usr/bin/dvault
	install -m 755 $(DIST_DIR)/datavault-agent /usr/bin/datavault-agent
	install -m 755 $(DIST_DIR)/datavault-server /usr/bin/datavault-server
	install -m 644 scripts/datavault-agent.service /etc/systemd/system/
	install -m 644 scripts/datavault-server.service /etc/systemd/system/
	install -d -m 750 /var/log/datavault
	install -m 640 /dev/null /var/log/datavault/agent.log
	install -m 644 scripts/datavault-agent.logrotate /etc/logrotate.d/datavault-agent
	systemctl daemon-reload
