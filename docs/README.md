# Documentation

This directory holds the operator and maintainer reference material that sits
behind the top-level `README.md`.

## Operator Docs

- [`architecture.md`](./architecture.md): how the runtime rewrites requests,
  injects the KeyClaw notice, and resolves placeholders on the way back
- [`configuration.md`](./configuration.md): config-file schema, environment
  variables, and precedence rules
- [`secret-patterns.md`](./secret-patterns.md): detector coverage, placeholder
  shape, allowlist behavior, and testing notes for `src/sensitive.rs`
- [`threat-model.md`](./threat-model.md): assets, trust boundaries, expected
  adversaries, and residual risk
- [`macos-gui-apps.md`](./macos-gui-apps.md): the supported path for
  Finder-launched macOS apps

## Maintainer Docs

- [`release/maintainer-checklist.md`](./release/maintainer-checklist.md):
  release checklist for versioning, verification, publication, and rollback
- [`plans/`](./plans/): archived plans, verification notes, and design records

## Read This First

If you are new to KeyClaw, start in this order:

1. [`../README.md`](../README.md)
2. [`configuration.md`](./configuration.md)
3. [`architecture.md`](./architecture.md)
4. [`threat-model.md`](./threat-model.md)

If you are changing detection behavior, also read:

1. [`secret-patterns.md`](./secret-patterns.md)
2. [`../CONTRIBUTING.md`](../CONTRIBUTING.md)
