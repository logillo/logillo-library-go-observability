package obs

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// logSink installs a JSON default logger at DEBUG for the test and returns
// the entries it wrote, newest last.
type logSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func installLogSink(t *testing.T) *logSink {
	t.Helper()
	sink := &logSink{}
	prev := slog.Default()
	slog.SetDefault(slog.New(&ctxHandler{inner: slog.NewJSONHandler(&lockedWriter{sink: sink}, &slog.HandlerOptions{Level: slog.LevelDebug})}))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return sink
}

type lockedWriter struct{ sink *logSink }

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.sink.mu.Lock()
	defer w.sink.mu.Unlock()
	return w.sink.buf.Write(p)
}

func (s *logSink) entries(t *testing.T, msg string) []map[string]any {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(s.buf.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("log line is not json: %s", line)
		}
		if msg == "" || m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

// memoryArchive keeps stored records in memory.
type memoryArchive struct {
	mu      sync.Mutex
	objects map[string][]byte
	fail    bool
}

func (a *memoryArchive) Store(_ context.Context, name string, record []byte) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail {
		return "", io.ErrClosedPipe
	}
	if a.objects == nil {
		a.objects = map[string][]byte{}
	}
	a.objects[name] = record
	return "gs://test/" + name, nil
}

func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestOutboundExchangeIsCapturedWithSecretsBlanked(t *testing.T) {
	sink := installLogSink(t)
	var received []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "session=abc")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"bookingID":"RAPI1","accessToken":"tok"}`))
	}))
	defer server.Close()

	client := NewCapturer("carrier-a").Client(5 * time.Second)
	body := `{"customerId":"1","customerKey":"s3cret","consigneeParty":{"address":{"name1":"Ida"}}}`
	req, _ := http.NewRequestWithContext(WithRequestID(context.Background(), "req-1"), http.MethodPost, server.URL+"/booking/road/v1/bookings?apiKey=qqq", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != `{"bookingID":"RAPI1","accessToken":"tok"}` {
		t.Fatalf("caller must receive the whole body, got %s", got)
	}
	if string(received) != body {
		t.Fatalf("server must receive the whole body, got %s", received)
	}

	entries := sink.entries(t, "exchange")
	if len(entries) != 1 {
		t.Fatalf("want one exchange record, got %d", len(entries))
	}
	e := entries[0]
	if e["capture"] != "exchange" || e["direction"] != "outbound" || e["peer"] != "carrier-a" || e["status"] != float64(201) || e["requestId"] != "req-1" {
		t.Errorf("record = %v", e)
	}
	if strings.Contains(e["url"].(string), "qqq") {
		t.Errorf("query secret survived: %s", e["url"])
	}
	request := e["request"].(map[string]any)
	if request["headers"].(map[string]any)["Authorization"] != redacted {
		t.Errorf("authorization header survived: %v", request["headers"])
	}
	reqBody := request["body"].(map[string]any)
	if reqBody["customerKey"] != redacted || reqBody["customerId"] != "1" {
		t.Errorf("request body = %v", reqBody)
	}
	response := e["response"].(map[string]any)
	if response["headers"].(map[string]any)["Set-Cookie"] != redacted {
		t.Errorf("cookie survived: %v", response["headers"])
	}
	if response["body"].(map[string]any)["accessToken"] != redacted || response["body"].(map[string]any)["bookingID"] != "RAPI1" {
		t.Errorf("response body = %v", response["body"])
	}
	if raw := sink.buf.String(); strings.Contains(raw, "s3cret") || strings.Contains(raw, "Bearer secret") || strings.Contains(raw, `"tok"`) {
		t.Error("a secret reached the log output")
	}
}

func TestArchivedExchangeIsStoredUnderTheRequestAndLinkedFromTheLog(t *testing.T) {
	sink := installLogSink(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	archive := &memoryArchive{}
	cap := NewCapturer("carrier-a", ArchiveTo(archive))
	cap.now = func() time.Time { return mustTime("2026-10-07T09:39:03.895Z") }

	ctx := WithRequestID(context.Background(), "01a115bb-1250-7a0f-9b29-83b9292d8295")
	ctx = ContextWithAttrs(ctx, slog.String("shipmentReference", "SHP-261007-2SGY7"))
	ctx = WithArchiving(WithOperation(ctx, "booking.create"))
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/bookings", strings.NewReader(`{"a":1}`))
	if _, err := cap.Client(5 * time.Second).Do(req); err != nil {
		t.Fatal(err)
	}

	wantPrefix := "carrier-a/2026-10-07/01a115bb-1250-7a0f-9b29-83b9292d8295/093903.895-booking.create-"
	var wantName string
	var stored []byte
	for name, record := range archive.objects {
		if strings.HasPrefix(name, wantPrefix) {
			wantName, stored = name, record
		}
	}
	if wantName == "" {
		t.Fatalf("archive holds %v, want a name under %s", keys(archive.objects), wantPrefix)
	}
	var rec map[string]any
	if err := json.Unmarshal(stored, &rec); err != nil {
		t.Fatal(err)
	}
	if rec["requestId"] != "01a115bb-1250-7a0f-9b29-83b9292d8295" || rec["operation"] != "booking.create" || rec["peer"] != "carrier-a" {
		t.Errorf("archived record = %v", rec)
	}
	if rec["attributes"].(map[string]any)["shipmentReference"] != "SHP-261007-2SGY7" {
		t.Errorf("business keys must ride into the archive: %v", rec["attributes"])
	}
	e := sink.entries(t, "exchange")[0]
	if e["archived"] != "gs://test/"+wantName || e["operation"] != "booking.create" || e["shipmentReference"] != "SHP-261007-2SGY7" {
		t.Errorf("log record = %v", e)
	}
}

func TestArchiveFailureIsLoggedAndNeverFailsTheCall(t *testing.T) {
	sink := installLogSink(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{}`)) }))
	defer server.Close()
	cap := NewCapturer("carrier-a", ArchiveTo(&memoryArchive{fail: true}))
	req, _ := http.NewRequestWithContext(WithArchiving(context.Background()), http.MethodPost, server.URL, nil)
	resp, err := cap.Client(5 * time.Second).Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("call must succeed: %v %v", resp, err)
	}
	if e := sink.entries(t, "exchange")[0]; e["archiveError"] == nil || e["archived"] != nil {
		t.Errorf("record = %v", e)
	}
	if len(sink.entries(t, "exchange archive failed")) != 1 {
		t.Error("the failure must be logged on its own line")
	}
}

func TestRepeatedAnswersAreCapturedOnlyWhenTheyChange(t *testing.T) {
	sink := installLogSink(t)
	var answer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(answer))
	}))
	defer server.Close()
	client := NewCapturer("carrier-a").Client(5 * time.Second)
	ctx := WithChangeKey(context.Background(), "tracking:00840451498000072909")
	poll := func() {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/track", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.ReadAll(resp.Body)
	}
	answer = `{"status":"in_transit"}`
	poll()
	poll()
	answer = `{"status":"delivered"}`
	poll()

	entries := sink.entries(t, "exchange")
	if len(entries) != 3 {
		t.Fatalf("want 3 records, got %d", len(entries))
	}
	first, second, third := entries[0], entries[1], entries[2]
	if first["unchanged"] != nil || first["response"].(map[string]any)["body"] == nil || first["level"] != "INFO" {
		t.Errorf("first answer must be captured in full: %v", first)
	}
	if second["unchanged"] != true || second["response"].(map[string]any)["body"] != nil || second["level"] != "DEBUG" {
		t.Errorf("repeated answer must be a bodiless DEBUG line: %v", second)
	}
	if third["unchanged"] != nil || third["response"].(map[string]any)["body"].(map[string]any)["status"] != "delivered" {
		t.Errorf("changed answer must be captured in full: %v", third)
	}
	for _, e := range entries {
		if e["changeKey"] != "tracking:00840451498000072909" {
			t.Errorf("every record names its change key: %v", e)
		}
	}
}

func TestTransportFailureIsRecordedAsAWarning(t *testing.T) {
	sink := installLogSink(t)
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close()
	req, _ := http.NewRequest(http.MethodGet, url+"/x", nil)
	if _, err := NewCapturer("carrier-b").Client(time.Second).Do(req); err == nil {
		t.Fatal("call must fail")
	}
	e := sink.entries(t, "exchange")[0]
	if e["level"] != "WARN" || e["error"] == nil || e["response"] != nil || e["peer"] != "carrier-b" {
		t.Errorf("record = %v", e)
	}
}

func TestPeerAndOperationResolveFromContextThenRequest(t *testing.T) {
	sink := installLogSink(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{}`)) }))
	defer server.Close()
	cap := NewCapturer("",
		PeerFromRequest(func(r *http.Request) string { return "host:" + r.URL.Host }),
		OperationFromRequest(func(r *http.Request) string { return r.Method + " " + r.URL.Path }),
	)
	client := cap.Client(time.Second)

	req, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/shipment-quotes", nil)
	_, _ = client.Do(req)
	req, _ = http.NewRequestWithContext(WithPeer(WithOperation(context.Background(), "quote"), "carrier-c"), http.MethodGet, server.URL+"/api/v1/shipment-quotes", nil)
	_, _ = client.Do(req)

	entries := sink.entries(t, "exchange")
	if entries[0]["peer"] != "host:"+strings.TrimPrefix(server.URL, "http://") || entries[0]["operation"] != "GET /api/v1/shipment-quotes" {
		t.Errorf("request-derived: %v", entries[0])
	}
	if entries[1]["peer"] != "carrier-c" || entries[1]["operation"] != "quote" {
		t.Errorf("context wins: %v", entries[1])
	}
}

func TestInboundCaptureKeepsWhatTheServiceDecides(t *testing.T) {
	sink := installLogSink(t)
	archive := &memoryArchive{}
	cap := NewCapturer("api", ArchiveTo(archive))

	var handled []byte
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handled, _ = io.ReadAll(r.Body)
		SetActorAPIKeyID(r.Context(), "key-1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"ship-1","token":"t"}`))
	})
	decide := func(r *http.Request, status int) InboundDecision {
		write := r.Method != http.MethodGet
		return InboundDecision{Log: write || ActorAPIKeyID(r.Context()) != "", Archive: write && ActorAPIKeyID(r.Context()) != "", Operation: "shipments.create"}
	}
	mux := AccessLogMiddleware(cap.Inbound(decide)(handler))

	rec := httptest.NewRecorder()
	body := `{"recipientName":"Ida","password":"p"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/shipments?apiKey=zz", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	mux.ServeHTTP(rec, req)

	if string(handled) != body {
		t.Fatalf("handler must read the whole body, got %s", handled)
	}
	if rec.Code != http.StatusCreated || rec.Body.String() != `{"id":"ship-1","token":"t"}` {
		t.Fatalf("response altered: %d %s", rec.Code, rec.Body.String())
	}
	entries := sink.entries(t, "exchange")
	if len(entries) != 1 {
		t.Fatalf("want one record, got %d", len(entries))
	}
	e := entries[0]
	if e["direction"] != "inbound" || e["peer"] != "api" || e["operation"] != "shipments.create" || e["status"] != float64(201) {
		t.Errorf("record = %v", e)
	}
	if e["request"].(map[string]any)["body"].(map[string]any)["password"] != redacted {
		t.Errorf("request secret survived: %v", e["request"])
	}
	if e["response"].(map[string]any)["body"].(map[string]any)["token"] != redacted {
		t.Errorf("response secret survived: %v", e["response"])
	}
	if len(archive.objects) != 1 {
		t.Errorf("an API-key write must be archived, archive holds %v", keys(archive.objects))
	}
	for _, stored := range archive.objects {
		var r map[string]any
		_ = json.Unmarshal(stored, &r)
		if r["actor"].(map[string]any)["apiKeyId"] != "key-1" {
			t.Errorf("archived record must name the actor: %v", r["actor"])
		}
	}
}

func TestInboundCaptureSkipsWhatTheServiceDeclinesAndHealthProbes(t *testing.T) {
	sink := installLogSink(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`[]`)) })
	mux := NewCapturer("api").Inbound(func(r *http.Request, _ int) InboundDecision {
		return InboundDecision{Log: r.Method != http.MethodGet}
	})(handler)
	for _, path := range []string{"/api/v1/shipments", "/api/v1/health"} {
		mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
	}
	if n := len(sink.entries(t, "exchange")); n != 0 {
		t.Errorf("declined requests must leave no record, got %d", n)
	}
}

func TestInboundStreamingResponsesAreRecordedBySizeOnly(t *testing.T) {
	sink := installLogSink(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		for i := 0; i < 3; i++ {
			_, _ = w.Write([]byte("data: {\"quote\":1}\n\n"))
			w.(http.Flusher).Flush()
		}
	})
	mux := NewCapturer("api").Inbound(func(*http.Request, int) InboundDecision { return InboundDecision{Log: true} })(handler)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/shipment-pricings:quote", strings.NewReader(`{"x":1}`)))
	if !rec.Flushed || rec.Body.Len() == 0 {
		t.Fatal("stream must reach the client flushed")
	}
	e := sink.entries(t, "exchange")[0]
	response := e["response"].(map[string]any)
	if response["body"] != "<stream>" || response["bytes"] != float64(rec.Body.Len()) {
		t.Errorf("stream must be recorded by size: %v", response)
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestRequestIDIsForwardedOnlyWhenAsked(t *testing.T) {
	installLogSink(t)
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get(RequestIDHeader))
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	ctx := WithRequestID(context.Background(), "req-7")
	for _, c := range []*Capturer{NewCapturer("carrier"), NewCapturer("adapter", ForwardRequestID())} {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
		if _, err := c.Client(time.Second).Do(req); err != nil {
			t.Fatal(err)
		}
	}
	if seen[0] != "" || seen[1] != "req-7" {
		t.Errorf("carrier call must carry no id, adapter call the request's: %v", seen)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	req.Header.Set(RequestIDHeader, "explicit")
	_, _ = NewCapturer("adapter", ForwardRequestID()).Client(time.Second).Do(req)
	if seen[2] != "explicit" {
		t.Errorf("an id the caller set is kept: %v", seen)
	}
}

func TestArchiveAndChangeKeyCanBeDecidedPerRequest(t *testing.T) {
	sink := installLogSink(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"s":1}`)) }))
	defer server.Close()
	archive := &memoryArchive{}
	c := NewCapturer("adapter", ArchiveTo(archive),
		ArchiveWhen(func(r *http.Request) bool { return strings.HasSuffix(r.URL.Path, "/shipment-bookings") }),
		ChangeKeyFromRequest(func(r *http.Request) string {
			if strings.Contains(r.URL.Path, "/tracking/") {
				return "tracking:" + r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			}
			return ""
		}),
	)
	client := c.Client(time.Second)
	for _, path := range []string{"/api/v1/shipment-bookings", "/api/v1/tracking/ABC", "/api/v1/tracking/ABC", "/api/v1/services"} {
		req, _ := http.NewRequest(http.MethodPost, server.URL+path, strings.NewReader(`{}`))
		if _, err := client.Do(req); err != nil {
			t.Fatal(err)
		}
	}
	if len(archive.objects) != 1 {
		t.Errorf("only the booking is archived, archive holds %v", keys(archive.objects))
	}
	entries := sink.entries(t, "exchange")
	if entries[1]["changeKey"] != "tracking:ABC" || entries[2]["unchanged"] != true || entries[3]["changeKey"] != nil {
		t.Errorf("change keys by path: %v %v %v", entries[1]["changeKey"], entries[2]["unchanged"], entries[3]["changeKey"])
	}
}

func TestInheritRequestContextCarriesIdentityNotCancellation(t *testing.T) {
	src, cancel := context.WithCancel(WithRequestID(context.Background(), "req-9"))
	src = ContextWithAttrs(withActor(src), slog.String("shipmentReference", "SHP-1"))
	SetActorAPIKeyID(src, "key-9")
	dst := InheritRequestContext(context.Background(), src)
	cancel()
	if dst.Err() != nil {
		t.Fatal("the detached context must not be cancelled with its source")
	}
	if RequestID(dst) != "req-9" || ActorAPIKeyID(dst) != "key-9" {
		t.Errorf("id and actor must carry over: %q %q", RequestID(dst), ActorAPIKeyID(dst))
	}
	if attrs := contextAttrs(dst); len(attrs) != 1 || attrs[0].Key != "shipmentReference" {
		t.Errorf("log keys must carry over: %v", attrs)
	}
}
