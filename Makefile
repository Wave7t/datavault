.PHONY: build proto clean install

BINARIES = dvault datavault-agent datavault-server
CMDS = cmd/dvault cmd/datavault-agent cmd/datavault-server

build: proto
	for cmd in $(CMDS); do \
		go build -o dist/$$(basename $$cmd) ./$$cmd; \
	done

proto:
	buf generate

test:
	go test ./... -v -count=1

clean:
	rm -rf dist/

install: build
	install -m 755 dist/dvault /usr/bin/dvault
	install -m 755 dist/datavault-agent /usr/bin/datavault-agent
	install -m 755 dist/datavault-server /usr/bin/datavault-server
	install -m 644 scripts/datavault-agent.service /etc/systemd/system/
	install -m 644 scripts/datavault-server.service /etc/systemd/system/
	systemctl daemon-reload
