// Package obs is the observability layer every Logillo service runs on:
// structured logging (slog) and distributed tracing (OpenTelemetry) with
// Google Cloud Observability as the destination, one request id carried
// across services, and the capture of what is exchanged at each service
// boundary — what a client sent, what a service sent an adapter, what an
// adapter sent a carrier and what came back.
//
// Logging: InitLogging installs a slog default logger — JSON in Cloud
// Logging's structured format when running on Cloud Run (or LOG_FORMAT=json),
// human-readable text locally. Every record logged with a request context
// carries the request id and the active trace/span, so a log line in Logs
// Explorer links to its trace and every line of one request shares an id.
// Setting the slog default also routes the `log` package through the same
// handler, so plain log.Printf call sites emit structured lines at INFO.
//
// Tracing: InitTracing installs the OTel tracer provider + W3C trace-context
// propagation. On GCP spans export to Cloud Trace; locally spans are created
// (so log correlation works) but not exported.
//
// Capture: Transport records every outbound HTTP exchange of the client it
// wraps; CaptureInbound records the inbound exchanges a service chooses to
// keep. Both write one "exchange" record with the request and response in
// full, secrets blanked and files reduced to a size and fingerprint, and
// optionally a copy into the exchange archive. See exchange.go.
//
// Severity convention for absorbed failures (an error the code logs and
// continues past): a failure whose effect is retried or tolerated (poller
// item skipped until the next cycle, rate limiter failing open) logs WARN
// with the attr pair `"swallowed", true` — the swallowed-failures log metric
// counts these and alerts on a sustained rate. A failure whose side effect
// is lost for good (an event publish that has no retry, a parked outbox row)
// logs ERROR — the severity alert fires per occurrence.
package obs

import (
	"context"
	"log/slog"
	"os"
	"time"

	"cloud.google.com/go/compute/metadata"
	"go.opentelemetry.io/otel/trace"
)

// projectID is resolved once at InitLogging / InitTracing and shared: it
// prefixes the Cloud Logging trace field and selects the Cloud Trace export
// project.
var projectID string

// onCloudRun reports whether the process runs on Cloud Run (K_SERVICE is set
// on every Cloud Run revision).
func onCloudRun() bool {
	return os.Getenv("K_SERVICE") != ""
}

// resolveProjectID returns the GCP project id: GOOGLE_CLOUD_PROJECT when
// set, otherwise the metadata server when on Cloud Run, otherwise empty
// (local development).
func resolveProjectID() string {
	if p := os.Getenv("GOOGLE_CLOUD_PROJECT"); p != "" {
		return p
	}
	if !onCloudRun() {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p, err := metadata.ProjectIDWithContext(ctx)
	if err != nil {
		return ""
	}
	return p
}

// serviceNameOr prefers the Cloud Run service name (K_SERVICE) so telemetry
// matches the deployed identity, falling back to the compiled-in name.
func serviceNameOr(fallback string) string {
	if name := os.Getenv("K_SERVICE"); name != "" {
		return name
	}
	return fallback
}

// InitLogging installs the process-wide slog default logger and returns it.
// serviceName is stamped on every record so the shared Logs Explorer view
// can filter by application even where the resource labels are absent.
// level is the minimum level written.
func InitLogging(serviceName string, level slog.Level) *slog.Logger {
	projectID = resolveProjectID()

	format := os.Getenv("LOG_FORMAT")
	useJSON := format == "json" || (format == "" && onCloudRun())

	var inner slog.Handler
	if useJSON {
		inner = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level:       level,
			ReplaceAttr: replaceForCloudLogging,
		})
	} else {
		inner = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	}

	logger := slog.New(&ctxHandler{inner: inner.WithAttrs([]slog.Attr{
		slog.String("service", serviceNameOr(serviceName)),
	})})
	slog.SetDefault(logger)
	return logger
}

// replaceForCloudLogging maps slog's built-in keys onto Cloud Logging's
// structured-payload special fields: `severity` drives the level filter and
// colouring, `message` is the display line.
func replaceForCloudLogging(groups []string, a slog.Attr) slog.Attr {
	if len(groups) > 0 {
		return a
	}
	switch a.Key {
	case slog.LevelKey:
		level, _ := a.Value.Any().(slog.Level)
		a.Key = "severity"
		a.Value = slog.StringValue(severityFor(level))
	case slog.MessageKey:
		a.Key = "message"
	}
	return a
}

func severityFor(level slog.Level) string {
	switch {
	case level >= slog.LevelError:
		return "ERROR"
	case level >= slog.LevelWarn:
		return "WARNING"
	case level >= slog.LevelInfo:
		return "INFO"
	default:
		return "DEBUG"
	}
}

// logAttrsKey carries request-scoped log attributes on the context — see
// ContextWithAttrs.
type logAttrsKey struct{}

// ContextWithAttrs returns a context whose log records (through the default
// logger's context-aware handler) additionally carry attrs. Middlewares bind
// the actor — the authenticated user, the acting party — and domain code
// binds the keys of the things a request works on — a shipment reference, a
// booking id, a carrier — so "every line about this shipment" is one filter.
//
// The library knows no business: which keys exist is each module's choice.
// The convention is `<thing>Id` for identifiers and `<thing>Reference` for
// human-readable references, so keys from different modules read alike.
func ContextWithAttrs(ctx context.Context, attrs ...slog.Attr) context.Context {
	existing, _ := ctx.Value(logAttrsKey{}).([]slog.Attr)
	merged := make([]slog.Attr, 0, len(existing)+len(attrs))
	merged = append(merged, existing...)
	merged = append(merged, attrs...)
	return context.WithValue(ctx, logAttrsKey{}, merged)
}

// contextAttrs returns the attrs bound with ContextWithAttrs.
func contextAttrs(ctx context.Context) []slog.Attr {
	attrs, _ := ctx.Value(logAttrsKey{}).([]slog.Attr)
	return attrs
}

// ctxHandler enriches every record from its context: the request id, any
// attrs bound via ContextWithAttrs, and the active OTel span. With a resolved
// project id the trace lands in Cloud Logging's correlation fields, so the
// line links to its Cloud Trace waterfall; without one (local dev) a plain
// traceId attribute keeps cross-service grep working.
type ctxHandler struct {
	inner slog.Handler
}

func (h *ctxHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *ctxHandler) Handle(ctx context.Context, record slog.Record) error {
	if id := RequestID(ctx); id != "" {
		record.AddAttrs(slog.String("requestId", id))
	}
	if attrs := contextAttrs(ctx); len(attrs) > 0 {
		record.AddAttrs(attrs...)
	}
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		if projectID != "" {
			record.AddAttrs(
				slog.String("logging.googleapis.com/trace", "projects/"+projectID+"/traces/"+sc.TraceID().String()),
				slog.String("logging.googleapis.com/spanId", sc.SpanID().String()),
				slog.Bool("logging.googleapis.com/trace_sampled", sc.IsSampled()),
			)
		} else {
			record.AddAttrs(slog.String("traceId", sc.TraceID().String()))
		}
	}
	return h.inner.Handle(ctx, record)
}

func (h *ctxHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ctxHandler{inner: h.inner.WithAttrs(attrs)}
}

func (h *ctxHandler) WithGroup(name string) slog.Handler {
	return &ctxHandler{inner: h.inner.WithGroup(name)}
}
