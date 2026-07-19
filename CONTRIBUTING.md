# Contributing to datavault

## Before you start

- Read the [development guide](docs/development.md) and the
  [server-test preflight](docs/server-test-preflight.md).
- Do not put certificates, private keys, backup data, SSH-agent sockets, or
  production hostnames in commits, issue reports, or test fixtures.
- Keep the Agent-to-Server security model intact: mTLS identifies a machine;
  user-authorized operations require the user's SSH signature.

## Development workflow

1. Create a focused branch from `main`.
2. Make changes and add or update tests for behavior changes.
3. Run the local quality checks:

   ```bash
   make fmt-check tidy-check proto-format-check proto-lint generate-check vet test-race
   ```

4. Update `README.md` and deployment documentation when commands,
   configuration, storage layout, or operational behavior changes.
5. For a change that affects binaries or deployment, run
   make release-linux-amd64 and check the generated bundle before merging.
6. Open a pull request using the provided template. Keep commits focused and
   use an imperative, scoped subject such as `fix: reject invalid archive path`.

## Protobuf changes

Generated files are checked in. When editing a `.proto` file, run
`buf format -w` and `buf generate`, then commit the generated code together
with the source change. New APIs must be backward compatible unless the pull
request explicitly documents a migration.

## Reporting vulnerabilities

Do not open a public issue for a security vulnerability. Follow the private
reporting instructions in [SECURITY.md](SECURITY.md).
