package forwardproxy

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestTrafficAuditLogCaddyfileDirective(t *testing.T) {
	const logPath = "/var/log/caddy-naive/traffic-audit.log"
	d := caddyfile.NewTestDispenser(`forward_proxy {
		basic_auth easewa supersecret
		traffic_audit_log ` + logPath + `
	}`)

	var h Handler
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}
	if h.TrafficAuditLogPath != logPath {
		t.Fatalf("TrafficAuditLogPath = %q, want %q", h.TrafficAuditLogPath, logPath)
	}
}

func TestTrafficAuditLogWritesTunnelRecordWithoutCredentials(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "traffic-audit.log")
	auditLog, err := newTrafficAuditLogger(logPath)
	if err != nil {
		t.Fatalf("newTrafficAuditLogger() error = %v", err)
	}
	h := Handler{trafficAuditLog: auditLog}

	req, err := http.NewRequest(http.MethodConnect, "https://www.youtube.com:443", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.RemoteAddr = "45.15.112.21:51324"
	req.Host = "www.youtube.com:443"
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	req.TLS = &tls.ConnectionState{ServerName: "alps.vetka.tech"}
	req.Header.Set("Proxy-Authorization", "Basic ZWFzZXdhOnN1cGVyc2VjcmV0")
	req.Header.Set("Authorization", "Bearer another-secret")

	h.logTrafficAudit(req, "easewa", "www.youtube.com:443", tunnelTraffic{
		ClientToTarget: 1234567,
		TargetToClient: 987654321,
	}, 2*time.Minute)
	if err := auditLog.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	logText := string(data)
	for _, forbidden := range []string{
		"supersecret",
		"Proxy-Authorization",
		"Authorization",
		"another-secret",
		"Basic ",
		"ZWFzZXdhOnN1cGVyc2VjcmV0",
	} {
		if strings.Contains(logText, forbidden) {
			t.Fatalf("traffic audit log contains forbidden credential material %q", forbidden)
		}
	}

	lines := strings.Split(strings.TrimSpace(logText), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d traffic audit lines, want 1: %q", len(lines), logText)
	}

	var record trafficAuditRecord
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatalf("Unmarshal() error = %v; line = %q", err, lines[0])
	}
	if record.Event != "connect_closed" {
		t.Fatalf("Event = %q, want connect_closed", record.Event)
	}
	if record.Username != "easewa" {
		t.Fatalf("Username = %q, want easewa", record.Username)
	}
	if record.RemoteIP != "45.15.112.21" {
		t.Fatalf("RemoteIP = %q, want 45.15.112.21", record.RemoteIP)
	}
	if record.Method != http.MethodConnect {
		t.Fatalf("Method = %q, want CONNECT", record.Method)
	}
	if record.Host != "www.youtube.com:443" {
		t.Fatalf("Host = %q, want www.youtube.com:443", record.Host)
	}
	if record.URI != "www.youtube.com:443" {
		t.Fatalf("URI = %q, want www.youtube.com:443", record.URI)
	}
	if record.Proto != "HTTP/2.0" {
		t.Fatalf("Proto = %q, want HTTP/2.0", record.Proto)
	}
	if record.ServerName != "alps.vetka.tech" {
		t.Fatalf("ServerName = %q, want alps.vetka.tech", record.ServerName)
	}
	if record.BytesClientToTarget != 1234567 {
		t.Fatalf("BytesClientToTarget = %d, want 1234567", record.BytesClientToTarget)
	}
	if record.BytesTargetToClient != 987654321 {
		t.Fatalf("BytesTargetToClient = %d, want 987654321", record.BytesTargetToClient)
	}
	if record.BytesTotal != 988888888 {
		t.Fatalf("BytesTotal = %d, want 988888888", record.BytesTotal)
	}
	if record.DurationMS != 120000 {
		t.Fatalf("DurationMS = %d, want 120000", record.DurationMS)
	}
}

func TestTrafficAuditLogAbsentDoesNotCreateFile(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "traffic-audit.log")
	h := Handler{}

	req, err := http.NewRequest(http.MethodConnect, "https://www.youtube.com:443", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.RemoteAddr = "45.15.112.21:51324"

	h.logTrafficAudit(req, "easewa", "www.youtube.com:443", tunnelTraffic{
		ClientToTarget: 1,
		TargetToClient: 2,
	}, time.Second)

	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("Stat(%q) error = %v, want not exist", logPath, err)
	}
}
