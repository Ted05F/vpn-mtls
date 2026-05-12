#!/usr/bin/env bash
# docker/vault-init/init.sh — bootstraps Vault PKI engine for VPN mTLS
# Runs once as a Docker init container after Vault becomes healthy.
set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-root-dev-token}"
CERTS_OUT="/certs"

export VAULT_ADDR VAULT_TOKEN

log()  { echo "[vault-init] $*"; }
die()  { echo "[vault-init] ERROR: $*" >&2; exit 1; }

# Wait for Vault to be truly ready
wait_vault() {
  log "Waiting for Vault..."
  for i in $(seq 1 30); do
    if vault status 2>/dev/null | grep -q "Initialized"; then
      log "Vault ready."
      return 0
    fi
    sleep 2
  done
  die "Vault did not become ready in time"
}

# ── Enable PKI secrets engine ─────────────────────────────────────────────────
enable_pki() {
  log "Enabling PKI secrets engine..."
  vault secrets enable -path=pki pki 2>/dev/null || log "PKI already enabled"
  vault secrets tune -max-lease-ttl=87600h pki

  # Generate internal Root CA
  vault write -field=certificate pki/root/generate/internal \
    common_name="VPN Root CA" \
    issuer_name="vpn-root" \
    ttl=87600h > "${CERTS_OUT}/ca.pem"
  log "Root CA generated: ${CERTS_OUT}/ca.pem"

  # Configure CA and CRL URLs
  vault write pki/config/urls \
    issuing_certificates="${VAULT_ADDR}/v1/pki/ca" \
    crl_distribution_points="${VAULT_ADDR}/v1/pki/crl"
}

# ── Create PKI roles ──────────────────────────────────────────────────────────
create_roles() {
  log "Creating PKI roles..."

  # Server role
  vault write pki/roles/vpn-server \
    issuer_ref="$(vault read -field=default pki/config/issuers)" \
    allowed_domains="vpn-server.internal,localhost" \
    allow_subdomains=false \
    allow_bare_domains=true \
    allow_ip_sans=true \
    server_flag=true \
    client_flag=false \
    key_type=rsa \
    key_bits=4096 \
    max_ttl=8760h \
    ttl=8760h

  # Client role
  vault write pki/roles/vpn-client \
    issuer_ref="$(vault read -field=default pki/config/issuers)" \
    allowed_domains="vpn.internal" \
    allow_subdomains=true \
    allow_bare_domains=false \
    server_flag=false \
    client_flag=true \
    key_type=rsa \
    key_bits=4096 \
    max_ttl=8760h \
    ttl=8760h

  log "PKI roles created: vpn-server, vpn-client"
}

# ── Issue initial server certificate ─────────────────────────────────────────
issue_server_cert() {
  log "Issuing server certificate..."
  vault write -format=json pki/issue/vpn-server \
    common_name="vpn-server.internal" \
    alt_names="localhost" \
    ip_sans="127.0.0.1,172.20.0.20" \
    ttl=8760h > /tmp/server_cert.json

  python3 -c "
import json, sys
d = json.load(open('/tmp/server_cert.json'))['data']
open('${CERTS_OUT}/server.pem', 'w').write(d['certificate'])
open('${CERTS_OUT}/server.key', 'w').write(d['private_key'])
open('${CERTS_OUT}/ca.pem', 'w').write(d['issuing_ca'])
print('Server cert serial:', d['serial_number'])
"
  log "Server cert written to ${CERTS_OUT}/server.pem"
}

# ── Issue demo client certificate ─────────────────────────────────────────────
issue_client_cert() {
  local name="${1:-demo-client}"
  log "Issuing client certificate for ${name}..."
  vault write -format=json pki/issue/vpn-client \
    common_name="${name}.vpn.internal" \
    ttl=8760h > "/tmp/${name}_cert.json"

  python3 -c "
import json, sys
name = '${name}'
d = json.load(open(f'/tmp/{name}_cert.json'))['data']
open('${CERTS_OUT}/{name}.pem'.format(name=name), 'w').write(d['certificate'])
open('${CERTS_OUT}/{name}.key'.format(name=name), 'w').write(d['private_key'])
print(f'Client cert serial: {d[\"serial_number\"]}')
"
  log "Client cert written to ${CERTS_OUT}/${name}.pem"
}

# ── Create Vault policies ─────────────────────────────────────────────────────
create_policies() {
  log "Creating Vault policies..."

  vault policy write vpn-server - <<'EOF'
path "pki/issue/vpn-server" { capabilities = ["create", "update"] }
path "pki/issue/vpn-client" { capabilities = ["create", "update"] }
path "pki/cert/ca"          { capabilities = ["read"] }
path "pki/revoke"           { capabilities = ["create", "update"] }
path "pki/crl/rotate"       { capabilities = ["create", "update"] }
path "secret/data/vpn/*"    { capabilities = ["create", "read", "update", "delete"] }
EOF

  vault policy write vpn-client - <<'EOF'
path "pki/issue/vpn-client" { capabilities = ["create", "update"] }
path "pki/cert/ca"          { capabilities = ["read"] }
path "secret/data/vpn/config" { capabilities = ["read"] }
EOF

  log "Policies created: vpn-server, vpn-client"
}

# ── Enable KV secrets engine ──────────────────────────────────────────────────
enable_kv() {
  log "Enabling KV-v2 secrets engine..."
  vault secrets enable -path=secret kv-v2 2>/dev/null || log "KV-v2 already enabled"

  # Store initial VPN config
  vault kv put secret/vpn/config \
    tun_subnet="10.8.0.0/24" \
    tun_gateway="10.8.0.1" \
    max_clients="254" \
    session_ttl="86400"
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
  wait_vault
  enable_pki
  create_roles
  create_policies
  enable_kv
  issue_server_cert
  issue_client_cert "demo-client"
  log "Vault PKI bootstrap complete."
}

main "$@"
