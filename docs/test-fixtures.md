# Integration Test Fixtures

mallcop-legion integration tests use the existing dogfood deployment infrastructure at `~/projects/mallcop-deploy/` for real-world testing. This document describes the available fixtures and how to load them.

## Overview

The mallcop-deploy project maintains a production-like infrastructure (dogfood) that serves as the source of truth for integration test fixtures. Tests load configuration from this fixture source rather than spinning up sandboxes or mocks.

**IMPORTANT:** mallcop-deploy is production dogfood, not a sandbox. Integration tests **must use read-only scans only** and never make destructive calls against the 3dl-dev organization.

## Configuration Source

All fixture values are stored in:
```
~/projects/mallcop-deploy/mallcop.yaml
```

This file is the single source of truth. Tests should load from this file at runtime rather than hardcoding values.

## GitHub App Authentication

### Fixture Details
- **Organization**: `3dl-dev`
- **Installation ID**: `116376961`
- **Secrets backend**: environment variables (`env`)

### Loading in Tests

GitHub app credentials are loaded via the secrets backend defined in `mallcop.yaml`:

```
secrets:
  backend: env
connectors:
  github:
    org: 3dl-dev
    installation_id: 116376961
```

To use in integration tests:
1. Read the `mallcop.yaml` file
2. Parse the `connectors.github.org` and `connectors.github.installation_id` values
3. Load GitHub app private key from environment variables via the configured secrets backend
4. The private key is NOT stored in the YAML file — it's loaded from `$GITHUB_APP_PRIVATE_KEY` (or similar env var) at runtime

See the secrets backend documentation (env provider) for how credentials are resolved.

### Usage Pattern

Tests using GitHub App auth:
1. Parse `org: 3dl-dev` and `installation_id: 116376961` from the YAML
2. Obtain the app private key from the secrets backend (env)
3. Use the app private key to generate JWT tokens for API calls
4. All GitHub scans are **read-only only** — no commits, no branch protection changes, no destructive mutations

## mallcop-pro Service Token

### Fixture Details
- **Source file**: `~/projects/mallcop-deploy/mallcop.yaml` → `pro.service_token`
- **API endpoint**: `pro.inference_url` = `https://api.mallcop.app`
- **Account endpoint**: `pro.account_url` = `https://api.mallcop.app/api/account`

### Loading in Tests

```yaml
pro:
  service_token: <value stored in mallcop.yaml>
  account_url: https://api.mallcop.app/api/account
  inference_url: https://api.mallcop.app
```

To use in integration tests:
1. Read the `mallcop.yaml` file
2. Extract `pro.service_token`, `pro.account_url`, and `pro.inference_url`
3. Use the service token for authentication to mallcop-pro API endpoints
4. Never hardcode these values; always load from the fixture source

### Usage Pattern

Tests calling mallcop-pro:
1. Load the service token from `pro.service_token` in the YAML
2. Authenticate to `pro.inference_url` (https://api.mallcop.app)
3. Use read-only operations only (querying results, fetching account info)
4. Never trigger scans, create new keys, or modify account state during tests

## Delivery Campfire

### Fixture Details
- **Campfire ID**: `04c0d27f975b24c3233206637f6a399f3467d44c9c390636bcbb9f59acabff9e`
- **Source file**: `~/projects/mallcop-deploy/mallcop.yaml` → `delivery.campfire_id`

### Loading in Tests

```yaml
delivery:
  campfire_id: 04c0d27f975b24c3233206637f6a399f3467d44c9c390636bcbb9f59acabff9e
```

To use in integration tests:
1. Read the `mallcop.yaml` file
2. Extract `delivery.campfire_id`
3. Use this ID to post findings to the delivery campfire during test runs

### Usage Pattern

Tests that verify delivery integration:
1. Load the campfire ID from the YAML
2. Post a test finding to the campfire
3. Verify the message was delivered (read-only verification)
4. Do not create, modify, or delete findings—only verify delivery

## Telegram Delivery

### Fixture Details
- **Source file**: `~/projects/mallcop-deploy/mallcop.yaml` → `delivery.telegram_bot_token` and `delivery.telegram_chat_id`
- **Bot token**: Stored as `delivery.telegram_bot_token` (secret value, not exposed in docs)
- **Chat ID**: Stored as `delivery.telegram_chat_id` (numeric ID, not exposed in docs)

### Loading in Tests

```yaml
delivery:
  telegram_bot_token: <secret, loaded from YAML>
  telegram_chat_id: <numeric ID, loaded from YAML>
```

To use in integration tests:
1. Read the `mallcop.yaml` file
2. Extract `delivery.telegram_bot_token` and `delivery.telegram_chat_id`
3. Use the bot token to authenticate to Telegram Bot API
4. Post test messages to the chat ID

### Usage Pattern

Tests that verify Telegram delivery:
1. Load the bot token and chat ID from the YAML
2. Send a test message to the chat via Telegram Bot API
3. Verify the message was delivered (read-only verification)
4. Do not modify or delete messages—only verify delivery

## Integration Test Patterns

### Loading Fixture Values at Test Time

All integration tests should follow this pattern:

```go
// Load fixture configuration
configPath := os.ExpandEnv("$HOME/projects/mallcop-deploy/mallcop.yaml")
config, err := loadYAML(configPath)
if err != nil {
    t.Fatalf("failed to load fixture config: %v", err)
}

// Extract values from loaded config
githubOrg := config.Connectors.GitHub.Org
githubInstallationID := config.Connectors.GitHub.InstallationID
serviceToken := config.Pro.ServiceToken
campfireID := config.Delivery.CampfireID

// Use fixture values in test
```

### Test Isolation

- Tests must use the same fixture source (mallcop-deploy) to ensure consistency
- Tests should NOT modify the deployment state
- Tests should be idempotent—running the same test twice should produce the same result
- Use distinct test IDs or timestamps to avoid collisions in shared resources

### Secrets Handling

- **Never hardcode secrets** in test code
- **Never log or print secrets** (service tokens, API keys, bot tokens)
- Load secrets from environment variables or secure configuration backends
- The `secrets.backend: env` setting in mallcop.yaml indicates secrets are loaded via environment
- Tests that need secrets should verify they are present before running; skip the test gracefully if missing

## Caveats

### Production Dogfood, Not a Sandbox

mallcop-deploy is a real, production-like deployment used for internal testing. It is **not** a sandbox or test-only environment.

- **All scans run against real GitHub organizations** (3dl-dev is a real org we control)
- **Do not make destructive calls** — no branch pushes, no permission changes, no webhook modifications
- **Read-only operations only** — query findings, check scan status, verify delivery
- **Think before testing** — consider the impact on the real dogfood environment

### Fixtures Are Fixed

The fixture values (GitHub org, campfire ID, etc.) are fixed and shared. All integration tests using these fixtures run against the same real endpoints. This is by design—it ensures tests are realistic and catch real integration issues—but it also means tests must cooperate and not interfere with each other.

## Related Documentation

- **mallcop-deploy secrets management**: `~/projects/mallcop-deploy/CLAUDE.md`
- **ClankerOS worker isolation**: `~/projects/clankeros/docs/guide.md`
- **Campfire protocol**: `~/projects/campfire/docs/protocol.md`
