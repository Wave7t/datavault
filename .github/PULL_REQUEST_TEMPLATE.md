## Summary

Describe the change and why it is needed.

## Validation

- [ ] `make fmt-check`
- [ ] `make tidy-check`
- [ ] `make generate-check` (when Protobuf sources changed)
- [ ] `make vet`
- [ ] `make test-race`
- [ ] Documentation and deployment instructions are updated, if applicable.

## Security and operations

- [ ] This change does not log secrets, private keys, nonces, or backup contents.
- [ ] I considered authentication, authorization, path validation, quota, and restore implications.
