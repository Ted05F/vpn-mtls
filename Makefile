# Makefile — VPN mTLS project automation
.PHONY: all build up down pki vault-init test bench lint clean logs

# ── Config ────────────────────────────────────────────────────────────────────
BINARY_SERVER = bin/vpn-server
BINARY_CLIENT = bin/vpn-client
DOCKER_COMPOSE = docker compose
GO_FLAGS = -ldflags="-s -w"

# ── Build ─────────────────────────────────────────────────────────────────────
all: build

build: build-server build-client

build-server:
	@echo "→ Building VPN server..."
	CGO_ENABLED=0 GOOS=linux go build $(GO_FLAGS) -o $(BINARY_SERVER) ./cmd/server

build-client:
	@echo "→ Building VPN client..."
	CGO_ENABLED=0 GOOS=linux go build $(GO_FLAGS) -o $(BINARY_CLIENT) ./cmd/client

# ── Docker ────────────────────────────────────────────────────────────────────
up:
	@cp -n .env.example .env 2>/dev/null || true
	$(DOCKER_COMPOSE) up -d --build
	@echo "→ Stack started. Run 'make logs' to follow output."

down:
	$(DOCKER_COMPOSE) down -v

restart:
	$(DOCKER_COMPOSE) restart vpn_server vpn_client

logs:
	$(DOCKER_COMPOSE) logs -f

logs-server:
	$(DOCKER_COMPOSE) logs -f vpn_server

logs-client:
	$(DOCKER_COMPOSE) logs -f vpn_client

# ── PKI ───────────────────────────────────────────────────────────────────────
pki:
	@echo "→ Bootstrapping PKI..."
	bash pki/scripts/bootstrap_pki.sh all

pki-client:
	@read -p "Client name: " name; \
	bash pki/scripts/bootstrap_pki.sh client "$$name"

pki-revoke:
	@read -p "Cert path to revoke: " path; \
	bash pki/scripts/bootstrap_pki.sh revoke "$$path"

# ── Vault ─────────────────────────────────────────────────────────────────────
vault-init:
	$(DOCKER_COMPOSE) run --rm vault_init

vault-status:
	$(DOCKER_COMPOSE) exec vault vault status

vault-ui:
	@echo "→ Vault UI: http://localhost:8200 (token: $$(grep VAULT_TOKEN .env | cut -d= -f2))"

# ── Tests ─────────────────────────────────────────────────────────────────────
test:
	go test ./... -v -count=1 -timeout 30s

test-security:
	go test ./benchmark/... -v -run "TestMTLS|TestTLS|TestSession|TestPort" -timeout 60s

test-short:
	go test ./... -short -count=1

# ── Benchmarks ────────────────────────────────────────────────────────────────
bench:
	go test ./benchmark/... -bench=. -benchmem -benchtime=5s

bench-handshake:
	go test ./benchmark/... -bench=BenchmarkTLSHandshake -benchmem -benchtime=10s -count=3

bench-throughput:
	go test ./benchmark/... -bench=BenchmarkThroughput -benchmem -benchtime=10s

# ── Code quality ──────────────────────────────────────────────────────────────
lint:
	golangci-lint run ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

# ── Security audit ────────────────────────────────────────────────────────────
audit:
	@echo "→ Running govulncheck..."
	govulncheck ./...
	@echo "→ Running gosec..."
	gosec ./...

# ── TLS verification ─────────────────────────────────────────────────────────
verify-tls:
	@echo "→ Verifying TLS configuration..."
	openssl s_client \
	  -connect localhost:8443 \
	  -cert pki/output/certs/demo-client.cert.pem \
	  -key  pki/output/certs/demo-client.key.pem \
	  -CAfile pki/output/intermediate/certs/ca-chain.cert.pem \
	  -tls1_3 -brief 2>&1 | head -30

verify-certs:
	@echo "→ Verifying certificate chain..."
	openssl verify \
	  -CAfile pki/output/intermediate/certs/ca-chain.cert.pem \
	  pki/output/certs/vpn-server.cert.pem
	openssl verify \
	  -CAfile pki/output/intermediate/certs/ca-chain.cert.pem \
	  pki/output/certs/demo-client.cert.pem

# ── Cleanup ───────────────────────────────────────────────────────────────────
clean:
	rm -rf bin/ pki/output/
	$(DOCKER_COMPOSE) down -v --remove-orphans

# ── Help ──────────────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "  VPN mTLS Project — Makefile Targets"
	@echo "  ─────────────────────────────────────"
	@echo "  make up            Start the full Docker stack"
	@echo "  make down          Stop and remove all containers"
	@echo "  make pki           Bootstrap PKI (Root CA → Intermediate → Certs)"
	@echo "  make vault-init    Initialise Vault PKI engine"
	@echo "  make test          Run all unit tests"
	@echo "  make test-security Run security-focused tests"
	@echo "  make bench         Run all benchmarks"
	@echo "  make verify-tls    Test live TLS connection"
	@echo "  make audit         Run govulncheck + gosec"
	@echo "  make clean         Remove build artefacts and volumes"
	@echo ""
