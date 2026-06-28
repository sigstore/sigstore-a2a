# Example Agent Cards

This directory contains example A2A Agent Card JSON files for testing and demonstration.

## Unsigned Agent Cards

- `georoute-agent.json` - GeoSpatial Route Planner Agent
- `data-analysis-agent.json` - Data Analysis Agent

## Signed Agent Cards (Staging)

Pre-signed examples using Sigstore **staging** environment with the [sigstore-conformance testing token](https://storage.googleapis.com/sigstore-conformance-testing-token/untrusted-testing-token.txt) identity.

- `signed-georoute-agent.json`
- `signed-data-analysis-agent.json`

### Verifying

```bash
sigstore-a2a verify examples/signed-georoute-agent.json \
  --staging \
  --identity_provider https://accounts.google.com \
  --identity "untrusted-sa@sigstore-conformance.iam.gserviceaccount.com"
```

## Usage

### Signing

```bash
sigstore-a2a sign examples/georoute-agent.json --output signed.json
```

### Verifying

```bash
sigstore-a2a verify signed.json --identity_provider <issuer> --identity <identity>
```

## CI/CD

These agent cards are automatically signed and verified in CI using production Sigstore.
