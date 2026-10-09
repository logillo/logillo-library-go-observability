package obs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// A span's URL attributes reach the trace store with their secrets
// blanked: the HTTP instrumentation records the full URL of a client call,
// query and all.
func TestExportedSpansCarryNoSignedQuery(t *testing.T) {
	mem := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(redactingExporter{inner: mem}))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	server := httptest.NewServer(otelhttp.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }), "server"))
	defer server.Close()
	client := &http.Client{Transport: otelhttp.NewTransport(http.DefaultTransport)}
	resp, err := client.Get(server.URL + "/api?ApiId=1&timestamp=2&signature=s3cret")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if err := provider.ForceFlush(context.Background()); err != nil {
		t.Fatal(err)
	}
	spans := mem.GetSpans()
	if len(spans) < 2 {
		t.Fatalf("spans = %d", len(spans))
	}
	var urls int
	for _, s := range spans {
		for _, kv := range s.Attributes {
			v := kv.Value.AsString()
			if strings.Contains(v, "s3cret") {
				t.Errorf("span %s attribute %s carries the signature: %s", s.Name, kv.Key, v)
			}
			if strings.Contains(string(kv.Key), "url") && strings.Contains(v, "timestamp=2") {
				urls++
			}
		}
	}
	if urls == 0 {
		t.Error("no url attribute kept the readable parameters")
	}
}
