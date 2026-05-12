#!/usr/bin/env bash
# pki/scripts/bootstrap_pki.sh
# ─────────────────────────────────────────────────────────────────────────────
# Bootstrap a full PKI hierarchy for the VPN mTLS system:
#   Root CA  →  Intermediate CA  →  Server cert + Client cert
#
# Outputs all material to ./pki/output/
# Requires: openssl 3.x
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_DIR="${SCRIPT_DIR}/../output"
CONF_DIR="${SCRIPT_DIR}/../configs"

ROOT_DIR="${PKI_DIR}/root"
INT_DIR="${PKI_DIR}/intermediate"
CERTS_DIR="${PKI_DIR}/certs"
DAYS_ROOT=3650    # 10 years
DAYS_INT=1825     # 5 years
DAYS_LEAF=365     # 1 year

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[PKI]${NC} $*"; }
warn() { echo -e "${YELLOW}[PKI]${NC} $*"; }
die()  { echo -e "${RED}[PKI ERROR]${NC} $*" >&2; exit 1; }

# ── Directory scaffold ────────────────────────────────────────────────────────
setup_dirs() {
  for dir in \
    "${ROOT_DIR}"/{certs,crl,newcerts,private} \
    "${INT_DIR}"/{certs,crl,csr,newcerts,private} \
    "${CERTS_DIR}"; do
    mkdir -p "$dir"
  done
  chmod 700 "${ROOT_DIR}/private" "${INT_DIR}/private"

  # Serial / index files required by openssl ca
  [[ -f "${ROOT_DIR}/serial" ]]        || echo 1000 > "${ROOT_DIR}/serial"
  [[ -f "${ROOT_DIR}/index.txt" ]]     || touch "${ROOT_DIR}/index.txt"
  [[ -f "${ROOT_DIR}/crlnumber" ]]     || echo 1000 > "${ROOT_DIR}/crlnumber"
  [[ -f "${INT_DIR}/serial" ]]         || echo 2000 > "${INT_DIR}/serial"
  [[ -f "${INT_DIR}/index.txt" ]]      || touch "${INT_DIR}/index.txt"
  [[ -f "${INT_DIR}/crlnumber" ]]      || echo 2000 > "${INT_DIR}/crlnumber"
}

# ── Root CA ───────────────────────────────────────────────────────────────────
create_root_ca() {
  log "Generating Root CA key and self-signed certificate..."
  openssl genrsa -out "${ROOT_DIR}/private/ca.key.pem" 4096
  chmod 400 "${ROOT_DIR}/private/ca.key.pem"

  openssl req -config "${CONF_DIR}/root_ca.cnf" \
    -key "${ROOT_DIR}/private/ca.key.pem" \
    -new -x509 -days ${DAYS_ROOT} -sha256 -extensions v3_ca \
    -out "${ROOT_DIR}/certs/ca.cert.pem" \
    -subj "/C=RU/ST=Moscow/O=VPN Research Lab/OU=PKI/CN=VPN Root CA"

  log "Root CA certificate:"
  openssl x509 -noout -text -in "${ROOT_DIR}/certs/ca.cert.pem" | grep -E "Subject:|Not (Before|After)"
}

# ── Intermediate CA ───────────────────────────────────────────────────────────
create_intermediate_ca() {
  log "Generating Intermediate CA key and CSR..."
  openssl genrsa -out "${INT_DIR}/private/intermediate.key.pem" 4096
  chmod 400 "${INT_DIR}/private/intermediate.key.pem"

  openssl req -config "${CONF_DIR}/intermediate_ca.cnf" \
    -key "${INT_DIR}/private/intermediate.key.pem" \
    -new -sha256 \
    -out "${INT_DIR}/csr/intermediate.csr.pem" \
    -subj "/C=RU/ST=Moscow/O=VPN Research Lab/OU=PKI/CN=VPN Intermediate CA"

  log "Signing Intermediate CA with Root CA..."
  openssl ca -config "${CONF_DIR}/root_ca.cnf" \
    -extensions v3_intermediate_ca \
    -days ${DAYS_INT} -notext -md sha256 \
    -in "${INT_DIR}/csr/intermediate.csr.pem" \
    -out "${INT_DIR}/certs/intermediate.cert.pem" \
    -batch

  # Build certificate chain
  cat "${INT_DIR}/certs/intermediate.cert.pem" \
      "${ROOT_DIR}/certs/ca.cert.pem" \
    > "${INT_DIR}/certs/ca-chain.cert.pem"

  log "Verifying intermediate CA chain..."
  openssl verify -CAfile "${ROOT_DIR}/certs/ca.cert.pem" \
    "${INT_DIR}/certs/intermediate.cert.pem"
}

# ── Server certificate ────────────────────────────────────────────────────────
create_server_cert() {
  local name="vpn-server"
  log "Generating server certificate: ${name}..."

  openssl genrsa -out "${CERTS_DIR}/${name}.key.pem" 4096
  chmod 400 "${CERTS_DIR}/${name}.key.pem"

  openssl req -config "${CONF_DIR}/server_cert.cnf" \
    -key "${CERTS_DIR}/${name}.key.pem" \
    -new -sha256 \
    -out "${CERTS_DIR}/${name}.csr.pem" \
    -subj "/C=RU/ST=Moscow/O=VPN Research Lab/OU=Server/CN=vpn-server.internal"

  openssl ca -config "${CONF_DIR}/intermediate_ca.cnf" \
    -extensions server_cert \
    -days ${DAYS_LEAF} -notext -md sha256 \
    -in "${CERTS_DIR}/${name}.csr.pem" \
    -out "${CERTS_DIR}/${name}.cert.pem" \
    -batch

  log "Verifying server certificate chain..."
  openssl verify -CAfile "${INT_DIR}/certs/ca-chain.cert.pem" \
    "${CERTS_DIR}/${name}.cert.pem"
}

# ── Client certificate ────────────────────────────────────────────────────────
create_client_cert() {
  local name="${1:-vpn-client}"
  log "Generating client certificate: ${name}..."

  openssl genrsa -out "${CERTS_DIR}/${name}.key.pem" 4096
  chmod 400 "${CERTS_DIR}/${name}.key.pem"

  openssl req -config "${CONF_DIR}/client_cert.cnf" \
    -key "${CERTS_DIR}/${name}.key.pem" \
    -new -sha256 \
    -out "${CERTS_DIR}/${name}.csr.pem" \
    -subj "/C=RU/ST=Moscow/O=VPN Research Lab/OU=Client/CN=${name}.vpn.internal"

  openssl ca -config "${CONF_DIR}/intermediate_ca.cnf" \
    -extensions usr_cert \
    -days ${DAYS_LEAF} -notext -md sha256 \
    -in "${CERTS_DIR}/${name}.csr.pem" \
    -out "${CERTS_DIR}/${name}.cert.pem" \
    -batch

  log "Verifying client certificate chain..."
  openssl verify -CAfile "${INT_DIR}/certs/ca-chain.cert.pem" \
    "${CERTS_DIR}/${name}.cert.pem"
}

# ── PKCS#12 bundle (optional) ─────────────────────────────────────────────────
create_p12() {
  local name="${1:-vpn-client}"
  log "Creating PKCS#12 bundle for ${name}..."
  openssl pkcs12 -export \
    -in  "${CERTS_DIR}/${name}.cert.pem" \
    -inkey "${CERTS_DIR}/${name}.key.pem" \
    -certfile "${INT_DIR}/certs/ca-chain.cert.pem" \
    -out "${CERTS_DIR}/${name}.p12" \
    -passout pass:changeme
}

# ── CRL generation ────────────────────────────────────────────────────────────
generate_crl() {
  log "Generating Certificate Revocation List..."
  openssl ca -config "${CONF_DIR}/intermediate_ca.cnf" \
    -gencrl -out "${INT_DIR}/crl/intermediate.crl.pem"
}

# ── Revoke a certificate ──────────────────────────────────────────────────────
revoke_cert() {
  local cert_path="${1:?usage: revoke_cert <path-to-cert>}"
  warn "Revoking certificate: ${cert_path}"
  openssl ca -config "${CONF_DIR}/intermediate_ca.cnf" \
    -revoke "${cert_path}" -batch
  generate_crl
  log "Certificate revoked. Updated CRL at ${INT_DIR}/crl/intermediate.crl.pem"
}

# ── Verify a certificate ──────────────────────────────────────────────────────
verify_cert() {
  local cert_path="${1:?usage: verify_cert <path-to-cert>}"
  log "Verifying: ${cert_path}"
  openssl verify -CAfile "${INT_DIR}/certs/ca-chain.cert.pem" \
    -crl_check -CRLfile "${INT_DIR}/crl/intermediate.crl.pem" \
    "${cert_path}" && log "Certificate is VALID" || die "Certificate FAILED verification"
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
  local cmd="${1:-all}"
  case "$cmd" in
    all)
      setup_dirs
      create_root_ca
      create_intermediate_ca
      create_server_cert
      create_client_cert "demo-client"
      generate_crl
      log "PKI bootstrap complete. Certificates in ${PKI_DIR}"
      ;;
    client)
      create_client_cert "${2:-vpn-client}"
      ;;
    revoke)
      revoke_cert "${2:?provide cert path}"
      ;;
    verify)
      verify_cert "${2:?provide cert path}"
      ;;
    p12)
      create_p12 "${2:-vpn-client}"
      ;;
    *)
      echo "Usage: $0 {all|client <name>|revoke <cert>|verify <cert>|p12 <name>}"
      exit 1
      ;;
  esac
}

main "$@"
