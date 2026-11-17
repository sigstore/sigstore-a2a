#!/usr/bin/env bash

# Copyright 2025 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# test-otel.sh — validate that OTel tracing spans are exported to Jaeger.
#
# Installs sigstore-a2a from the local source tree with [otel] extras,
# runs sign/verify operations, then checks Jaeger for the expected spans.
#
# Prerequisites:
#   - Jaeger must be running:
#       docker run --rm -d --name jaeger -p 16686:16686 -p 4318:4318 jaegertracing/all-in-one:latest
#
# Usage:
#   ./scripts/tests/test-otel.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

JAEGER_URL="http://localhost:16686"
OTEL_SERVICE="sigstore-a2a"

echo "=== OTel Tracing Integration Tests ==="
echo

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------
for util in curl jq openssl pip; do
    if ! command -v "${util}" &>/dev/null; then
        echo "Error: required utility '${util}' not found in PATH"
        exit 1
    fi
done

# ---------------------------------------------------------------------------
# Install sigstore-a2a from source if not already installed
# ---------------------------------------------------------------------------
if ! command -v sigstore-a2a &>/dev/null; then
    echo "[Setup] Installing sigstore-a2a from source with [otel] extras..."
    pip install -e "${REPO_ROOT}[otel]" --quiet
    echo
fi

echo "Checking Jaeger reachability at ${JAEGER_URL}..."
if ! curl -sf "${JAEGER_URL}/api/services" > /dev/null 2>&1; then
    echo "Error: Jaeger is not reachable at ${JAEGER_URL}"
    echo "Start with: docker run --rm -d --name jaeger -p 16686:16686 -p 4318:4318 jaegertracing/all-in-one:latest"
    exit 1
fi
echo "Jaeger is reachable"
echo

# ---------------------------------------------------------------------------
# Temp directory and cleanup
# ---------------------------------------------------------------------------
TMPDIR=$(mktemp -d) || exit 1
cleanup() { rm -rf "${TMPDIR}"; }
trap cleanup EXIT QUIT

# ---------------------------------------------------------------------------
# Generate keys and certificate
# ---------------------------------------------------------------------------
echo "[Setup] Generating EC key pair and code-signing certificate..."
openssl ecparam -genkey -name prime256v1 -noout -out "${TMPDIR}/private.pem" 2>/dev/null
openssl ec -in "${TMPDIR}/private.pem" -pubout -out "${TMPDIR}/public.pem" 2>/dev/null
openssl req -x509 -new -key "${TMPDIR}/private.pem" -out "${TMPDIR}/cert.pem" -days 365 \
    -subj "/CN=OTel Test Signer" \
    -addext "keyUsage=digitalSignature" \
    -addext "extendedKeyUsage=codeSigning" 2>/dev/null
echo

# ---------------------------------------------------------------------------
# Create sample agent card
# ---------------------------------------------------------------------------
cat > "${TMPDIR}/agent-card.json" <<'EOF'
{
    "name": "otel-test-agent",
    "version": "1.0.0",
    "url": "https://example.com/agent",
    "skills": [{"id": "s1", "name": "Skill", "description": "A skill"}]
}
EOF

# =========================================================================
# PHASE 1: EC Key Sign and Verify
# =========================================================================
echo "=========================================="
echo "PHASE 1: EC Key Sign and Verify"
echo "=========================================="
echo

export OTEL_SERVICE_NAME="${OTEL_SERVICE}"
export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:4318"
export OTEL_EXPORTER_OTLP_PROTOCOL="http/protobuf"

echo "[Key] Signing agent card..."
sigstore-a2a sign key "${TMPDIR}/agent-card.json" \
    --private-key "${TMPDIR}/private.pem" \
    -o "${TMPDIR}/signed-key.json"
echo "[Key] Sign succeeded"

echo "[Key] Verifying agent card..."
sigstore-a2a verify key "${TMPDIR}/signed-key.json" \
    --public-key "${TMPDIR}/public.pem"
echo "[Key] Verify succeeded"
echo

# =========================================================================
# PHASE 2: Certificate Sign and Verify
# =========================================================================
echo "=========================================="
echo "PHASE 2: Certificate Sign and Verify"
echo "=========================================="
echo

echo "[Certificate] Signing agent card..."
sigstore-a2a sign certificate "${TMPDIR}/agent-card.json" \
    --private-key "${TMPDIR}/private.pem" \
    --signing-cert "${TMPDIR}/cert.pem" \
    --cert-chain "${TMPDIR}/cert.pem" \
    -o "${TMPDIR}/signed-cert.json"
echo "[Certificate] Sign succeeded"

echo "[Certificate] Verifying agent card..."
sigstore-a2a verify certificate "${TMPDIR}/signed-cert.json" \
    --cert-chain "${TMPDIR}/cert.pem"
echo "[Certificate] Verify succeeded"
echo

# =========================================================================
# PHASE 3: Validate Traces in Jaeger
# =========================================================================
echo "=========================================="
echo "PHASE 3: Validating Traces in Jaeger"
echo "=========================================="
echo

# Helper: query Jaeger with retries
jaeger_query_with_retry() {
    local url="$1"
    local jq_filter="$2"
    local description="$3"
    local max_attempts="${4:-10}"

    for i in $(seq 1 "${max_attempts}"); do
        local result
        result=$(curl -sf "${url}" | jq -r "${jq_filter}" 2>/dev/null) || true
        if [[ -n "${result}" && "${result}" != "null" && "${result}" != "0" && "${result}" != "false" ]]; then
            echo "${result}"
            return 0
        fi
        if [[ "${i}" -lt "${max_attempts}" ]]; then
            sleep 2
        fi
    done
    echo "Error: ${description} — not found after ${max_attempts} attempts" >&2
    return 1
}

TRACES_URL="${JAEGER_URL}/api/traces?service=${OTEL_SERVICE}&limit=20"

# --- 1. Service registered ---
echo "[Validate] Checking service '${OTEL_SERVICE}' is registered..."
service_check=$(jaeger_query_with_retry \
    "${JAEGER_URL}/api/services" \
    ".data | map(select(. == \"${OTEL_SERVICE}\")) | first" \
    "service '${OTEL_SERVICE}' not found in Jaeger")
if [[ "${service_check}" != "${OTEL_SERVICE}" ]]; then
    echo "Error: service '${OTEL_SERVICE}' not found in Jaeger"
    curl -sf "${JAEGER_URL}/api/services" | jq -r '.data[]'
    exit 1
fi
echo "  Service '${OTEL_SERVICE}': FOUND"

# --- 2. Sign span with method=key ---
echo "[Validate] Checking Sign span with method='key'..."
SIGN_KEY_FILTER='[.data[].spans[] | select(.operationName == "Sign") | select(.tags[] | select(.key == "signing.method" and .value == "key"))] | length'
sign_key_count=$(jaeger_query_with_retry "${TRACES_URL}" "${SIGN_KEY_FILTER}" "Sign span with method=key")
if [[ "${sign_key_count}" -lt 1 ]]; then
    echo "Error: No Sign span with signing.method=key found"
    exit 1
fi
echo "  Sign span (method=key): FOUND (${sign_key_count})"

# --- 3. Verify span with method=key ---
echo "[Validate] Checking Verify span with method='key'..."
VERIFY_KEY_FILTER='[.data[].spans[] | select(.operationName == "Verify") | select(.tags[] | select(.key == "verification.method" and .value == "key"))] | length'
verify_key_count=$(jaeger_query_with_retry "${TRACES_URL}" "${VERIFY_KEY_FILTER}" "Verify span with method=key")
if [[ "${verify_key_count}" -lt 1 ]]; then
    echo "Error: No Verify span with verification.method=key found"
    exit 1
fi
echo "  Verify span (method=key): FOUND (${verify_key_count})"

# --- 4. Sign span with method=certificate ---
echo "[Validate] Checking Sign span with method='certificate'..."
SIGN_CERT_FILTER='[.data[].spans[] | select(.operationName == "Sign") | select(.tags[] | select(.key == "signing.method" and .value == "certificate"))] | length'
sign_cert_count=$(jaeger_query_with_retry "${TRACES_URL}" "${SIGN_CERT_FILTER}" "Sign span with method=certificate")
if [[ "${sign_cert_count}" -lt 1 ]]; then
    echo "Error: No Sign span with signing.method=certificate found"
    exit 1
fi
echo "  Sign span (method=certificate): FOUND (${sign_cert_count})"

# --- 5. Verify span with method=certificate ---
echo "[Validate] Checking Verify span with method='certificate'..."
VERIFY_CERT_FILTER='[.data[].spans[] | select(.operationName == "Verify") | select(.tags[] | select(.key == "verification.method" and .value == "certificate"))] | length'
verify_cert_count=$(jaeger_query_with_retry "${TRACES_URL}" "${VERIFY_CERT_FILTER}" "Verify span with method=certificate")
if [[ "${verify_cert_count}" -lt 1 ]]; then
    echo "Error: No Verify span with verification.method=certificate found"
    exit 1
fi
echo "  Verify span (method=certificate): FOUND (${verify_cert_count})"

# =========================================================================
# Summary
# =========================================================================
echo
echo "=========================================="
echo "All OTel tracing tests PASSED"
echo "=========================================="
echo
echo "Summary:"
echo "  - Service '${OTEL_SERVICE}' registered in Jaeger"
echo "  - Sign spans:   key=${sign_key_count}, certificate=${sign_cert_count}"
echo "  - Verify spans:  key=${verify_key_count}, certificate=${verify_cert_count}"
echo

exit 0
