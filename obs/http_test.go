package obs

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A handler behind the tracing, the access log and the inbound capture
// reaches the connection through http.ResponseController, so a stream or a
// long wait can extend its write deadline past the server's.
func TestHandlerExtendsItsWriteDeadlineThroughEveryWrapper(t *testing.T) {
	installLogSink(t)
	capture := NewCapturer("api").Inbound(func(*http.Request, int) InboundDecision { return InboundDecision{Log: true} })
	server := httptest.NewServer(HTTPHandler(AccessLogMiddleware(capture(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Minute))
		_, _ = fmt.Fprint(w, err)
	})))))
	defer server.Close()

	resp, err := http.Get(server.URL + "/api/v1/shipments/shipment-quote-requests/x/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "<nil>" {
		t.Fatalf("extending the write deadline answered %q, want no error", body)
	}
}

// Health probes pass through the access log without a line, whatever shape
// a service gives its health route.
func TestAccessLogSkipsHealthProbes(t *testing.T) {
	sink := installLogSink(t)
	for _, path := range []string{"/health", "/healthz", "/api/v1/health", "/api/v1/health/live", "/api/v1/health/ready"} {
		AccessLogMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
	}
	if n := len(sink.entries(t, "http request")); n != 0 {
		t.Fatalf("health probes logged %d lines", n)
	}
}

// The access line names the caller the identity layer recorded further down
// the chain, and the address the request came from.
func TestAccessLogNamesTheActorAndTheClientAddress(t *testing.T) {
	sink := installLogSink(t)
	handler := AccessLogMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetActorUserID(r.Context(), "user-1")
		SetActorAPIKeyID(r.Context(), "key-1")
		w.WriteHeader(http.StatusTeapot)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/shipments", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	handler.ServeHTTP(httptest.NewRecorder(), req)
	e := sink.entries(t, "http request")[0]
	if e["userId"] != "user-1" || e["apiKeyId"] != "key-1" || e["clientIp"] != "203.0.113.9" || e["status"] != float64(418) {
		t.Errorf("access line = %v", e)
	}
}

// A request id arrives on the header when it is a UUID and is minted
// otherwise; either way the response echoes the one used.
func TestRequestIDMiddlewareHonoursOnlyUUIDs(t *testing.T) {
	var seen string
	handler := RequestIDMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = RequestID(r.Context())
	}))
	for _, supplied := range []string{"01a115bb-1250-7a0f-9b29-83b9292d8295", "not-an-id", ""} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if supplied != "" {
			req.Header.Set(RequestIDHeader, supplied)
		}
		handler.ServeHTTP(rec, req)
		if seen == "" || rec.Header().Get(RequestIDHeader) != seen {
			t.Errorf("supplied %q: context %q, echoed %q", supplied, seen, rec.Header().Get(RequestIDHeader))
		}
		if supplied == "01a115bb-1250-7a0f-9b29-83b9292d8295" && seen != supplied {
			t.Errorf("a UUID supplied by the caller is kept, got %q", seen)
		}
		if supplied == "not-an-id" && seen == supplied {
			t.Error("an arbitrary string is refused")
		}
	}
}
