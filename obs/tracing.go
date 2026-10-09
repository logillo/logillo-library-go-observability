package obs

import (
	"context"
	"fmt"

	texporter "github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/trace"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// InitTracing installs the global OTel tracer provider and W3C trace-context
// propagation, and returns a shutdown function that flushes pending spans.
//
// With a resolvable GCP project (Cloud Run, or GOOGLE_CLOUD_PROJECT set)
// spans export to Cloud Trace. Locally the provider runs without an
// exporter: spans still get real ids — so log lines carry a shared traceId
// across services — but nothing leaves the process.
//
// The sampler records every span. At the current traffic volume full
// fidelity is worth more than the export cost; revisit with a ratio sampler
// when production volume makes it matter.
func InitTracing(ctx context.Context, serviceName string) (func(context.Context) error, error) {
	if projectID == "" {
		projectID = resolveProjectID()
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(semconv.ServiceName(serviceNameOr(serviceName))),
	)
	if err != nil {
		return nil, fmt.Errorf("build otel resource: %w", err)
	}

	opts := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	}
	if projectID != "" {
		exporter, err := texporter.New(texporter.WithProjectID(projectID))
		if err != nil {
			return nil, fmt.Errorf("build cloud trace exporter: %w", err)
		}
		opts = append(opts, sdktrace.WithBatcher(redactingExporter{inner: exporter}))
	}

	provider := sdktrace.NewTracerProvider(opts...)
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return provider.Shutdown, nil
}

// urlAttributes are the span attributes that carry a URL or a query: the
// HTTP instrumentation writes the full URL of a client call, query and
// all, and a query may carry a signature or a token.
var urlAttributes = map[attribute.Key]bool{"url.full": true, "http.url": true}

// redactingExporter hands spans on with the secrets of their URL
// attributes blanked, so a signed query never reaches the trace store.
type redactingExporter struct {
	inner sdktrace.SpanExporter
}

func (e redactingExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	out := make([]sdktrace.ReadOnlySpan, len(spans))
	for i, s := range spans {
		out[i] = redactSpan(s)
	}
	return e.inner.ExportSpans(ctx, out)
}

func (e redactingExporter) Shutdown(ctx context.Context) error { return e.inner.Shutdown(ctx) }

// redactSpan returns the span with its URL attributes redacted, or the
// span itself when none carries a secret.
func redactSpan(s sdktrace.ReadOnlySpan) sdktrace.ReadOnlySpan {
	attrs := s.Attributes()
	var redactedAttrs []attribute.KeyValue
	for i, kv := range attrs {
		var value string
		switch {
		case urlAttributes[kv.Key]:
			value = redactURLString(kv.Value.AsString())
		case kv.Key == "http.target":
			value = redactQueriesIn(kv.Value.AsString())
		case kv.Key == "url.query":
			value = redactQuery(kv.Value.AsString())
		default:
			continue
		}
		if value == kv.Value.AsString() {
			continue
		}
		if redactedAttrs == nil {
			redactedAttrs = make([]attribute.KeyValue, len(attrs))
			copy(redactedAttrs, attrs)
		}
		redactedAttrs[i] = attribute.String(string(kv.Key), value)
	}
	if redactedAttrs == nil {
		return s
	}
	return redactedSpan{ReadOnlySpan: s, attrs: redactedAttrs}
}

// redactedSpan is a span whose attributes are read from a redacted copy.
type redactedSpan struct {
	sdktrace.ReadOnlySpan
	attrs []attribute.KeyValue
}

func (s redactedSpan) Attributes() []attribute.KeyValue { return s.attrs }
