# CLI Reference

The `sigstore-a2a` command-line interface provides commands for signing, verifying, and serving A2A Agent Cards.

## Global Options

```
sigstore-a2a [OPTIONS] COMMAND [ARGS]...
```

| Option | Description |
|--------|-------------|
| `--version` | Show version and exit |
| `-v, --verbose` | Enable verbose output |
| `-h, --help` | Show help message |

## Commands

### sign

Sign an A2A Agent Card using Sigstore keyless signing.

```bash
sigstore-a2a sign AGENT_CARD_JSON [OPTIONS]
```

#### Arguments

| Argument | Description |
|----------|-------------|
| `AGENT_CARD_JSON` | Path to the Agent Card JSON file to sign |

#### Options

| Option | Description |
|--------|-------------|
| `-o, --output PATH` | Output path for the signed Agent Card |
| `--use_ambient_credentials` | Use ambient CI/OIDC credentials if available |
| `--staging` | Use Sigstore staging trust roots |
| `--trust_config PATH` | Path to Sigstore ClientTrustConfig JSON |
| `--provenance` | Generate and embed SLSA provenance |
| `--identity_token TOKEN` | Fixed OIDC identity token to use |
| `--client_id ID` | OpenID Connect client ID for OAuth2 |
| `--client_secret SECRET` | OpenID Connect client secret for OAuth2 |
| `--repository OWNER/REPO` | Repository for provenance metadata |
| `--commit_sha SHA` | Commit SHA for provenance metadata |
| `--workflow_ref REF` | Workflow ref for provenance |

#### Examples

```bash
# Basic signing (will open browser for authentication)
sigstore-a2a sign agent-card.json

# Sign with specific output path
sigstore-a2a sign agent-card.json --output signed-card.json

# Sign using CI credentials (GitHub Actions, GitLab CI, etc.)
sigstore-a2a sign agent-card.json --use_ambient_credentials

# Sign with SLSA provenance
sigstore-a2a sign agent-card.json \
  --provenance \
  --repository myorg/myrepo \
  --commit_sha $GITHUB_SHA

# Sign using a pre-obtained identity token
sigstore-a2a sign agent-card.json --identity_token "$OIDC_TOKEN"

# Sign using staging environment
sigstore-a2a sign agent-card.json --staging

# Sign using custom trust configuration (private Sigstore)
sigstore-a2a sign agent-card.json --trust_config ./signing-config.json
```

---

### verify

Verify a signed Agent Card signature.

```bash
sigstore-a2a verify SIGNED_CARD_JSON [OPTIONS]
```

#### Arguments

| Argument | Description |
|----------|-------------|
| `SIGNED_CARD_JSON` | Path to the signed Agent Card JSON file |

#### Options

| Option | Description |
|--------|-------------|
| `--staging` | Use Sigstore staging environment |
| `--identity IDENTITY` | Expected identity of the signer |
| `--identity_provider URL` | **Required.** Expected OIDC issuer URL |
| `--repository OWNER/REPO` | Required repository constraint |
| `--workflow NAME` | Required workflow name constraint |
| `--trust_config PATH` | Path to custom trust configuration |

#### Examples

```bash
# Verify with GitHub Actions identity provider
sigstore-a2a verify signed-card.json \
  --identity_provider https://token.actions.githubusercontent.com

# Verify with repository constraint
sigstore-a2a verify signed-card.json \
  --identity_provider https://token.actions.githubusercontent.com \
  --repository sigstore/sigstore-a2a

# Verify with workflow constraint
sigstore-a2a verify signed-card.json \
  --identity_provider https://token.actions.githubusercontent.com \
  --repository sigstore/sigstore-a2a \
  --workflow "Release"

# Verify with Google identity
sigstore-a2a verify signed-card.json \
  --identity_provider https://accounts.google.com \
  --identity user@example.com
```

---

### serve

Serve a signed Agent Card at well-known endpoints.

```bash
sigstore-a2a serve SIGNED_CARD_JSON [OPTIONS]
```

#### Arguments

| Argument | Description |
|----------|-------------|
| `SIGNED_CARD_JSON` | Path to the signed Agent Card JSON file |

#### Options

| Option | Description |
|--------|-------------|
| `--host HOST` | Host to bind to (default: 127.0.0.1) |
| `--port PORT` | Port to bind to (default: 8080) |
| `--staging` | Use Sigstore staging environment for verification |
| `--no-verify` | Skip signature verification on startup |
| `--reload` | Enable auto-reload for development |

#### Endpoints

When running, the server exposes:

| Endpoint | Description |
|----------|-------------|
| `/.well-known/agent.json` | The Agent Card (without signature material) |
| `/.well-known/agent.signed.json` | The complete signed Agent Card |

#### Examples

```bash
# Serve on localhost
sigstore-a2a serve signed-card.json

# Serve on all interfaces
sigstore-a2a serve signed-card.json --host 0.0.0.0 --port 8080

# Serve without verification (for testing)
sigstore-a2a serve signed-card.json --no-verify
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |

## Environment Variables

The CLI respects the following environment variables:

| Variable | Description |
|----------|-------------|
| `SIGSTORE_ID_TOKEN` | OIDC identity token for signing |
| `GITHUB_TOKEN` | GitHub token (for ambient credentials) |
| `ACTIONS_ID_TOKEN_REQUEST_URL` | GitHub Actions OIDC URL |
| `ACTIONS_ID_TOKEN_REQUEST_TOKEN` | GitHub Actions OIDC token |

