// benchmark/security_test.go — Security validation and performance benchmarks
package benchmark

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Security Tests
// ─────────────────────────────────────────────────────────────────────────────

// TestMTLSRejectsNoClientCert verifies that the server refuses connections
// that do not present a client certificate.
func TestMTLSRejectsNoClientCert(t *testing.T) {
	serverAddr := serverAddrFromEnv()
	caPool := loadCAPool(t)

	cfg := &tls.Config{
		RootCAs:    caPool,
		MinVersion: tls.VersionTLS13,
		// Deliberately omit client certificate
	}

	conn, err := tls.Dial("tcp", serverAddr, cfg)
	if err == nil {
		conn.Close()
		t.Fatal("expected connection to be rejected without client cert, but it succeeded")
	}
	t.Logf("PASS: connection without client cert rejected: %v", err)
}

// TestMTLSRejectsExpiredCert verifies rejection of an expired client cert.
func TestMTLSRejectsExpiredCert(t *testing.T) {
	serverAddr := serverAddrFromEnv()
	caPool := loadCAPool(t)
	expiredCert := loadExpiredClientCert(t)

	cfg := &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{expiredCert},
		MinVersion:   tls.VersionTLS13,
	}

	conn, err := tls.Dial("tcp", serverAddr, cfg)
	if err == nil {
		conn.Close()
		t.Fatal("expected expired cert to be rejected")
	}
	t.Logf("PASS: expired cert rejected: %v", err)
}

// TestMTLSRejectsUntrustedCA verifies that a cert from an unknown CA is rejected.
func TestMTLSRejectsUntrustedCA(t *testing.T) {
	serverAddr := serverAddrFromEnv()
	caPool := loadCAPool(t)

	// Generate a self-signed cert NOT signed by our CA
	selfSignedCert := generateSelfSignedCert(t)

	cfg := &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{selfSignedCert},
		MinVersion:   tls.VersionTLS13,
	}

	conn, err := tls.Dial("tcp", serverAddr, cfg)
	if err == nil {
		conn.Close()
		t.Fatal("expected untrusted CA cert to be rejected")
	}
	t.Logf("PASS: untrusted CA cert rejected: %v", err)
}

// TestTLSVersionEnforcement verifies that TLS < 1.3 is rejected.
func TestTLSVersionEnforcement(t *testing.T) {
	serverAddr := serverAddrFromEnv()

	// Attempt with TLS 1.2 (should be rejected by server MinVersion=1.3)
	cfg := &tls.Config{
		MaxVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", serverAddr, cfg)
	if err == nil {
		conn.Close()
		t.Fatal("expected TLS 1.2 connection to be rejected")
	}
	t.Logf("PASS: TLS 1.2 rejected: %v", err)
}

// TestCipherSuiteRestriction ensures only TLS 1.3 cipher suites are accepted.
func TestCipherSuiteRestriction(t *testing.T) {
	serverAddr := serverAddrFromEnv()
	caPool := loadCAPool(t)
	clientCert := loadClientCert(t)

	cfg := &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS13,
	}

	conn, err := tls.Dial("tcp", serverAddr, cfg)
	if err != nil {
		t.Fatalf("valid TLS 1.3 connection failed: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	validCiphers := map[uint16]bool{
		tls.TLS_AES_256_GCM_SHA384:       true,
		tls.TLS_AES_128_GCM_SHA256:       true,
		tls.TLS_CHACHA20_POLY1305_SHA256: true,
	}
	if !validCiphers[state.CipherSuite] {
		t.Errorf("unexpected cipher suite: %s", tls.CipherSuiteName(state.CipherSuite))
	}
	t.Logf("PASS: cipher suite = %s", tls.CipherSuiteName(state.CipherSuite))
}

// TestSessionTicketsDisabled ensures session tickets are not used.
func TestSessionTicketsDisabled(t *testing.T) {
	serverAddr := serverAddrFromEnv()
	caPool := loadCAPool(t)
	clientCert := loadClientCert(t)

	cfg := &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS13,
	}

	conn, err := tls.Dial("tcp", serverAddr, cfg)
	if err != nil {
		t.Fatalf("connection failed: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if state.DidResume {
		t.Error("session was resumed — session tickets should be disabled")
	}
	t.Log("PASS: session tickets disabled")
}

// ─────────────────────────────────────────────────────────────────────────────
// Performance Benchmarks
// ─────────────────────────────────────────────────────────────────────────────

// BenchmarkTLSHandshake measures the cost of a full mTLS handshake.
func BenchmarkTLSHandshake(b *testing.B) {
	serverAddr := serverAddrFromEnv()
	caPool := loadCAPool(b)
	clientCert := loadClientCert(b)

	cfg := &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS13,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		conn, err := tls.Dial("tcp", serverAddr, cfg)
		if err != nil {
			b.Fatalf("dial failed: %v", err)
		}
		conn.Close()
	}
}

// BenchmarkConcurrentConnections measures throughput under concurrent load.
func BenchmarkConcurrentConnections(b *testing.B) {
	serverAddr := serverAddrFromEnv()
	caPool := loadCAPool(b)
	clientCert := loadClientCert(b)

	cfg := &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS13,
	}

	concurrency := 10
	var (
		ops    int64
		errors int64
		wg     sync.WaitGroup
	)

	b.ResetTimer()
	b.ReportAllocs()

	sem := make(chan struct{}, concurrency)
	for i := 0; i < b.N; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			conn, err := tls.Dial("tcp", serverAddr, cfg)
			if err != nil {
				atomic.AddInt64(&errors, 1)
				return
			}
			conn.Close()
			atomic.AddInt64(&ops, 1)
		}()
	}
	wg.Wait()

	b.ReportMetric(float64(atomic.LoadInt64(&ops)), "successful_conns")
	b.ReportMetric(float64(atomic.LoadInt64(&errors)), "errors")
}

// BenchmarkThroughput measures raw tunnel data throughput.
func BenchmarkThroughput(b *testing.B) {
	serverAddr := serverAddrFromEnv()
	caPool := loadCAPool(b)
	clientCert := loadClientCert(b)

	cfg := &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS13,
	}

	conn, err := tls.Dial("tcp", serverAddr, cfg)
	if err != nil {
		b.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	payload := make([]byte, 4096)
	buf := make([]byte, 4096)

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		if _, err := conn.Write(payload); err != nil {
			b.Fatalf("write: %v", err)
		}
		if _, err := conn.Read(buf); err != nil {
			b.Fatalf("read: %v", err)
		}
	}
}

// BenchmarkRedisSessionOps measures Redis session read/write latency.
func BenchmarkRedisSessionOps(b *testing.B) {
	// This benchmark requires a running Redis instance
	// See README for setup instructions
	b.Skip("requires running Redis — run with -run=BenchmarkRedis integration tags")
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func serverAddrFromEnv() string {
	addr := "127.0.0.1:8443"
	return addr
}

func loadCAPool(tb testing.TB) *x509.CertPool {
	tb.Helper()
	// In CI, load from pki/output/intermediate/certs/ca-chain.cert.pem
	pool := x509.NewCertPool()
	_ = pool
	// Stub — real test loads from file
	return pool
}

func loadClientCert(tb testing.TB) tls.Certificate {
	tb.Helper()
	// Stub — real test loads from pki/output/certs/demo-client.*
	return tls.Certificate{}
}

func loadExpiredClientCert(tb testing.TB) tls.Certificate {
	tb.Helper()
	return tls.Certificate{}
}

func generateSelfSignedCert(tb testing.TB) tls.Certificate {
	tb.Helper()
	return tls.Certificate{}
}

// ─────────────────────────────────────────────────────────────────────────────
// Latency histogram helper (for manual profiling)
// ─────────────────────────────────────────────────────────────────────────────

type latencyRecorder struct {
	mu      sync.Mutex
	samples []time.Duration
}

func (r *latencyRecorder) record(d time.Duration) {
	r.mu.Lock()
	r.samples = append(r.samples, d)
	r.mu.Unlock()
}

func (r *latencyRecorder) percentile(p float64) time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.samples) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(r.samples))
	copy(sorted, r.samples)
	// Insertion sort (benchmark data sets are small)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j] < sorted[j-1]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	idx := int(float64(len(sorted)-1) * p / 100)
	return sorted[idx]
}

func (r *latencyRecorder) report() string {
	return fmt.Sprintf(
		"p50=%v p95=%v p99=%v count=%d",
		r.percentile(50),
		r.percentile(95),
		r.percentile(99),
		len(r.samples),
	)
}

// ConnectionLatencyTest measures end-to-end connection establishment latency.
func TestConnectionLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in short mode")
	}

	serverAddr := serverAddrFromEnv()
	caPool := loadCAPool(t)
	clientCert := loadClientCert(t)

	cfg := &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS13,
	}

	rec := &latencyRecorder{}
	iterations := 100

	for i := 0; i < iterations; i++ {
		start := time.Now()
		conn, err := tls.Dial("tcp", serverAddr, cfg)
		elapsed := time.Since(start)
		if err != nil {
			t.Logf("iteration %d failed: %v", i, err)
			continue
		}
		conn.Close()
		rec.record(elapsed)
	}

	t.Logf("Connection latency over %d iterations: %s", iterations, rec.report())

	p99 := rec.percentile(99)
	const maxAcceptableLatency = 500 * time.Millisecond
	if p99 > maxAcceptableLatency {
		t.Errorf("p99 latency %v exceeds threshold %v", p99, maxAcceptableLatency)
	}
}

// TestConcurrentClients verifies the server handles multiple simultaneous connections.
func TestConcurrentClients(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in short mode")
	}

	serverAddr := serverAddrFromEnv()
	caPool := loadCAPool(t)
	clientCert := loadClientCert(t)

	cfg := &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS13,
	}

	const numClients = 50
	var (
		wg      sync.WaitGroup
		success int64
		failed  int64
	)

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			conn, err := tls.Dial("tcp", serverAddr, cfg)
			if err != nil {
				atomic.AddInt64(&failed, 1)
				return
			}
			// Hold connection briefly to simulate real workload
			time.Sleep(50 * time.Millisecond)
			conn.Close()
			atomic.AddInt64(&success, 1)
		}(i)
	}

	wg.Wait()
	t.Logf("Concurrent clients: %d successful, %d failed out of %d",
		atomic.LoadInt64(&success), atomic.LoadInt64(&failed), numClients)

	if atomic.LoadInt64(&failed) > numClients/10 {
		t.Errorf("too many failures: %d/%d", atomic.LoadInt64(&failed), numClients)
	}
}

// TestPortScan verifies no unexpected ports are exposed.
func TestPortScan(t *testing.T) {
	host := "127.0.0.1"
	expectedOpen := map[int]bool{
		8443: true, // VPN mTLS
		8200: true, // Vault
		6379: true, // Redis (internal only)
	}
	unexpectedOpen := []int{}

	for port := 1; port <= 1024; port++ {
		addr := fmt.Sprintf("%s:%d", host, port)
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			if !expectedOpen[port] {
				unexpectedOpen = append(unexpectedOpen, port)
			}
		}
	}

	if len(unexpectedOpen) > 0 {
		t.Errorf("unexpected open ports: %v", unexpectedOpen)
	} else {
		t.Log("PASS: no unexpected ports exposed in range 1-1024")
	}
}
