package checker

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"alertkick-poller/client"
)

func TestHTTPCheckRecordsTimingDetails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	m := &client.MonitorAssignment{
		UUID:        "test-uuid",
		Subdomain:   "test",
		MonitorType: "http",
		URL:         srv.URL,
		Location:    "hel1",
	}

	result := performHTTPCheck(m, false)
	if !result.Success {
		t.Fatalf("check failed: %s", result.ErrorMessage)
	}
	if result.Details == nil {
		t.Fatal("expected timing details on a successful check")
	}
	for _, key := range []string{"dns_time_ms", "connect_time_ms", "tls_time_ms", "first_byte_ms", "total_time_ms"} {
		v, ok := result.Details[key].(int64)
		if !ok {
			t.Errorf("missing or mistyped detail %q: %v", key, result.Details[key])
			continue
		}
		if v < 0 {
			t.Errorf("%s is negative: %d", key, v)
		}
	}
	// httptest serves loopback over plain HTTP: no TLS handshake happens.
	if tls := result.Details["tls_time_ms"].(int64); tls != 0 {
		t.Errorf("expected zero tls_time_ms for plain http, got %d", tls)
	}
	total := result.Details["total_time_ms"].(int64)
	first := result.Details["first_byte_ms"].(int64)
	if total < first {
		t.Errorf("total_time_ms (%d) < first_byte_ms (%d)", total, first)
	}
}

func TestHTTPCheckTLSTimingRecorded(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := &client.MonitorAssignment{
		UUID:        "test-uuid",
		Subdomain:   "test",
		MonitorType: "http",
		URL:         srv.URL,
		Location:    "hel1",
	}

	// tlsInsecure: the httptest server uses a self-signed cert.
	result := performHTTPCheck(m, true)
	if !result.Success {
		t.Fatalf("check failed: %s", result.ErrorMessage)
	}
	if result.Details == nil {
		t.Fatal("expected timing details")
	}
	if _, ok := result.Details["tls_time_ms"].(int64); !ok {
		t.Errorf("missing tls_time_ms detail: %v", result.Details["tls_time_ms"])
	}
}
