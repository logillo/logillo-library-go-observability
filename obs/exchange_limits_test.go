package obs

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// What the capture holds of a request, where the archive write runs, and
// what a repeated or failed answer is recorded as.

// The handler reads the whole body; the capture keeps a prefix and never
// reads ahead of the handler.
func TestInboundCaptureKeepsAPrefixAndStreamsTheRest(t *testing.T) {
	sink := installLogSink(t)
	body := bytes.Repeat([]byte("a"), captureLimit+4096)
	var seen int
	handler := NewCapturer("api").Inbound(func(*http.Request, int) InboundDecision { return InboundDecision{Log: true} })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got, _ := io.ReadAll(r.Body)
			seen = len(got)
			w.WriteHeader(http.StatusAccepted)
		}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/things", bytes.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	handler.ServeHTTP(httptest.NewRecorder(), req)
	if seen != len(body) {
		t.Fatalf("handler read %d of %d bytes", seen, len(body))
	}
	e := sink.entries(t, "exchange")[0]
	request := e["request"].(map[string]any)
	if request["bytes"] != float64(len(body)) || request["truncated"] != true {
		t.Errorf("request record = %v", request)
	}
	if s, ok := request["body"].(string); !ok || len(s) > defaultBodyLimit+8 {
		t.Errorf("log line holds %d bytes of body", len(s))
	}
}

// A handler that never reads the body leaves the capture with nothing to
// hold, and the record says how much arrived: nothing.
func TestInboundCaptureHoldsNothingTheHandlerDidNotRead(t *testing.T) {
	sink := installLogSink(t)
	handler := NewCapturer("api").Inbound(func(*http.Request, int) InboundDecision { return InboundDecision{Log: true} })(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/things", strings.NewReader(`{"password":"x"}`))
	handler.ServeHTTP(httptest.NewRecorder(), req)
	e := sink.entries(t, "exchange")[0]
	if request := e["request"].(map[string]any); request["bytes"] != float64(0) || request["body"] != nil {
		t.Errorf("request record = %v", request)
	}
}

// contextArchive records the context each write ran under.
type contextArchive struct {
	mu   sync.Mutex
	errs []error
	memoryArchive
}

func (a *contextArchive) Store(ctx context.Context, name string, record []byte) (string, error) {
	a.mu.Lock()
	a.errs = append(a.errs, ctx.Err())
	a.mu.Unlock()
	return a.memoryArchive.Store(ctx, name, record)
}

// The archive write outlives the request: a client that stopped waiting
// does not cost the record a dispute turns on.
func TestArchiveWriteRunsOnADetachedContext(t *testing.T) {
	installLogSink(t)
	archive := &contextArchive{}
	ctx, cancel := context.WithCancel(context.Background())
	handler := NewCapturer("api", ArchiveTo(archive)).Inbound(func(*http.Request, int) InboundDecision { return InboundDecision{Log: true, Archive: true} })(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			cancel()
			w.WriteHeader(http.StatusCreated)
		}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/v1/things", strings.NewReader(`{}`)).WithContext(ctx))
	if len(archive.errs) != 1 || archive.errs[0] != nil {
		t.Fatalf("archive ran under %v", archive.errs)
	}
	if len(archive.objects) != 1 {
		t.Fatalf("archived %d objects", len(archive.objects))
	}
}

// The archive keeps the bodies whole; the log line cuts them.
func TestArchiveKeepsWhatTheLogLineCuts(t *testing.T) {
	sink := installLogSink(t)
	archive := &memoryArchive{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	client := NewCapturer("carrier-a", ArchiveTo(archive), BodyLimit(200)).Client(time.Second)
	body := `{"items":"` + strings.Repeat("x", 1000) + `","customerKey":"s3cret"}`
	req, _ := http.NewRequestWithContext(WithArchiving(context.Background()), http.MethodPost, server.URL+"/bookings", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if _, err := client.Do(req); err != nil {
		t.Fatal(err)
	}
	e := sink.entries(t, "exchange")[0]
	request := e["request"].(map[string]any)
	if request["truncated"] != true || strings.Contains(request["body"].(string), "s3cret") {
		t.Errorf("log line = %v", request)
	}
	for _, object := range archive.objects {
		if !bytes.Contains(object, []byte(strings.Repeat("x", 1000))) || bytes.Contains(object, []byte("s3cret")) || bytes.Contains(object, []byte(`"truncated"`)) {
			t.Errorf("archive object = %s", object)
		}
	}
}

// A repeated failure stays a warning: an outage does not fade to DEBUG
// because the error page is the same every time.
func TestAnUnchangedFailureIsStillAWarning(t *testing.T) {
	sink := installLogSink(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("maintenance"))
	}))
	defer server.Close()
	client := NewCapturer("carrier-a").Client(time.Second)
	for range 2 {
		req, _ := http.NewRequestWithContext(WithChangeKey(context.Background(), "tracking:1"), http.MethodGet, server.URL+"/track/1", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	entries := sink.entries(t, "exchange")
	if len(entries) != 2 || entries[1]["unchanged"] != true || entries[1]["level"] != "WARN" {
		t.Errorf("records = %v", entries)
	}
}

// A per-call field the peer varies — a transaction id — is not a change.
func TestVolatileFieldsDoNotCountAsAChange(t *testing.T) {
	sink := installLogSink(t)
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"transactionId":"t-` + strings.Repeat("x", calls) + `","output":{"status":"IN_TRANSIT"}}`))
	}))
	defer server.Close()
	client := NewCapturer("carrier-a", VolatileFields("transactionId")).Client(time.Second)
	for range 2 {
		req, _ := http.NewRequestWithContext(WithChangeKey(context.Background(), "tracking:1"), http.MethodPost, server.URL+"/track", strings.NewReader(`{"n":["1"]}`))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	entries := sink.entries(t, "exchange")
	if len(entries) != 2 || entries[0]["unchanged"] == true || entries[1]["unchanged"] != true {
		t.Errorf("records = %v", entries)
	}
}

// The line names the actor the identity layer recorded, so "every
// exchange of API key X" is one filter.
func TestExchangeLineNamesTheActor(t *testing.T) {
	sink := installLogSink(t)
	handler := NewCapturer("api").Inbound(func(*http.Request, int) InboundDecision { return InboundDecision{Log: true} })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			SetActorAPIKeyID(r.Context(), "key-1")
			w.WriteHeader(http.StatusOK)
		}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/v1/things", strings.NewReader(`{}`)))
	e := sink.entries(t, "exchange")[0]
	if actor, _ := e["actor"].(map[string]any); actor["apiKeyId"] != "key-1" {
		t.Errorf("record = %v", e)
	}
}

// A nil archive, typed or not, keeps the no-op archive.
func TestATypedNilArchiveIsNoArchive(t *testing.T) {
	var g *GCSArchive
	c := NewCapturer("api", ArchiveTo(g), ArchiveTo(nil))
	if _, ok := c.archive.(NopArchive); !ok {
		t.Fatalf("archive = %T", c.archive)
	}
}

// A panic after the handler started its response leaves the response as
// it was: no envelope appended to a partial body.
func TestRecoverLeavesAStartedResponseAlone(t *testing.T) {
	installLogSink(t)
	rec := httptest.NewRecorder()
	RecoverMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("partial"))
		panic("boom")
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "partial" {
		t.Errorf("response = %d %q", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	RecoverMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") })).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), `"status":500`) {
		t.Errorf("response = %d %q", rec.Code, rec.Body.String())
	}
}

// A supplied id is kept in its canonical spelling.
func TestASuppliedRequestIDIsCanonical(t *testing.T) {
	var seen string
	handler := RequestIDMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { seen = RequestID(r.Context()) }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(RequestIDHeader, "urn:uuid:01A115BB-1250-7A0F-9B29-83B9292D8295")
	handler.ServeHTTP(httptest.NewRecorder(), req)
	if seen != "01a115bb-1250-7a0f-9b29-83b9292d8295" {
		t.Errorf("request id = %q", seen)
	}
}

// A request id with a slash does not nest archive folders.
func TestArchiveObjectNamesAreSafe(t *testing.T) {
	got := archiveObjectName("api", "POST /x", "a/b", mustTime("2026-10-07T09:39:03.895Z"), []byte("r"))
	if strings.Contains(got, "a/b") || strings.Count(got, "/") != 3 {
		t.Errorf("object name = %s", got)
	}
}
