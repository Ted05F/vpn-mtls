# docker/vault/config.hcl — Vault server configuration (production-like)
ui            = true
disable_mlock = true

storage "file" {
  path = "/vault/data"
}

listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_disable   = true   # TLS handled by Caddy in front; enable for direct access
}

api_addr     = "http://0.0.0.0:8200"
cluster_addr = "http://0.0.0.0:8201"

log_level = "Info"
log_file  = "/vault/logs/vault.log"

# Audit logging — write all requests/responses to file
# audit {
#   type = "file"
#   options = {
#     file_path = "/vault/logs/audit.log"
#   }
# }
