# Examples

## Python Examples

Runnable scripts demonstrating the library API:

### Sigstore Keyless Signing

Requires OIDC credentials (CI/CD ambient credentials or an explicit identity token):

```bash
# With an explicit identity token
python examples/sign_verify_sigstore.py examples/agent-cards/georoute-agent.json "$SIGSTORE_ID_TOKEN"

# In CI/CD with ambient credentials
python examples/sign_verify_sigstore.py examples/agent-cards/georoute-agent.json
```

### EC Key Signing

```bash
openssl ecparam -genkey -name prime256v1 -noout -out private.pem
openssl ec -in private.pem -pubout -out public.pem

python examples/sign_verify_ec_key.py private.pem public.pem examples/agent-cards/georoute-agent.json
```

### Certificate Signing

```bash
openssl ecparam -genkey -name prime256v1 -noout -out private.pem
openssl req -x509 -new -key private.pem -out cert.pem -days 365 \
  -subj "/CN=My Agent Signer" \
  -addext "keyUsage=digitalSignature" \
  -addext "extendedKeyUsage=codeSigning"

python examples/sign_verify_certificate.py private.pem cert.pem examples/agent-cards/georoute-agent.json
```

### Signing with SLSA Provenance

```bash
python examples/sign_with_provenance.py private.pem public.pem examples/agent-cards/georoute-agent.json
```

## Agent Cards

Sample A2A Agent Card JSON files are in `agent-cards/`:

- `georoute-agent.json` - GeoSpatial Route Planner Agent
- `data-analysis-agent.json` - Data Analysis Agent
- `signed-georoute-agent.json` - Pre-signed with Sigstore staging
- `signed-data-analysis-agent.json` - Pre-signed with Sigstore staging

### Verifying Pre-signed Cards

```bash
sigstore-a2a verify sigstore examples/agent-cards/signed-georoute-agent.json \
  --identity_provider https://accounts.google.com \
  --identity "untrusted-sa@sigstore-conformance.iam.gserviceaccount.com" \
  --staging
```
