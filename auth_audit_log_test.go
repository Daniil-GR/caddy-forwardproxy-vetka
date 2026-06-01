package forwardproxy

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestAuthAuditLogCaddyfileDirective(t *testing.T) {
	const logPath = "/var/log/caddy-naive/auth-audit.log"
	d := caddyfile.NewTestDispenser(`forward_proxy {
		basic_auth test_api supersecret
		auth_audit_log ` + logPath + `
	}`)

	var h Handler
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}
	if h.AuthAuditLogPath != logPath {
		t.Fatalf("AuthAuditLogPath = %q, want %q", h.AuthAuditLogPath, logPath)
	}
}

func TestAuthAuditLogWritesUsernameWithoutCredentials(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "auth-audit.log")
	auditLog, err := newAuthAuditLogger(logPath)
	if err != nil {
		t.Fatalf("newAuthAuditLogger() error = %v", err)
	}
	h := Handler{authAuditLog: auditLog}

	req, err := http.NewRequest(http.MethodConnect, "https://i.instagram.com:443", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.RemoteAddr = "45.15.112.21:51324"
	req.Host = "i.instagram.com:443"
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	req.TLS = &tls.ConnectionState{ServerName: "alps.vetka.tech"}
	req.Header.Set("Proxy-Authorization", "Basic dGVzdF9hcGk6c3VwZXJzZWNyZXQ=")
	req.Header.Set("Authorization", "Bearer another-secret")

	h.logAuthAudit(req, "test_api", "i.instagram.com:443")
	if err := auditLog.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if strings.Contains(string(data), "supersecret") {
		t.Fatal("audit log contains password")
	}
	if strings.Contains(string(data), "Proxy-Authorization") {
		t.Fatal("audit log contains Proxy-Authorization header name")
	}
	if strings.Contains(string(data), "Authorization") {
		t.Fatal("audit log contains Authorization header name")
	}
	if strings.Contains(string(data), "another-secret") {
		t.Fatal("audit log contains Authorization header value")
	}
	if strings.Contains(string(data), "Basic ") {
		t.Fatal("audit log contains Basic auth scheme")
	}
	if strings.Contains(string(data), "dGVzdF9hcGk6c3VwZXJzZWNyZXQ=") {
		t.Fatal("audit log contains raw Basic credentials")
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d audit lines, want 1: %q", len(lines), string(data))
	}

	var record authAuditRecord
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatalf("Unmarshal() error = %v; line = %q", err, lines[0])
	}
	if record.Username != "test_api" {
		t.Fatalf("Username = %q, want test_api", record.Username)
	}
	if record.RemoteIP != "45.15.112.21" {
		t.Fatalf("RemoteIP = %q, want 45.15.112.21", record.RemoteIP)
	}
	if record.Method != http.MethodConnect {
		t.Fatalf("Method = %q, want CONNECT", record.Method)
	}
	if record.Host != "i.instagram.com:443" {
		t.Fatalf("Host = %q, want i.instagram.com:443", record.Host)
	}
	if record.URI != "i.instagram.com:443" {
		t.Fatalf("URI = %q, want i.instagram.com:443", record.URI)
	}
	if record.Proto != "HTTP/2.0" {
		t.Fatalf("Proto = %q, want HTTP/2.0", record.Proto)
	}
	if record.ServerName != "alps.vetka.tech" {
		t.Fatalf("ServerName = %q, want alps.vetka.tech", record.ServerName)
	}
}
