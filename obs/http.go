package obs

import (
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// HTTPHandler wraps the server's root handler with OTel HTTP
// instrumentation: it extracts the inbound trace context (Cloud Run stamps
// one on every request; service-api propagates one to every adapter), starts
// the server span, and propagates the context to everything downstream. Wire
// it OUTSIDE the router so every middleware and handler sees the span.
func HTTPHandler(h http.Handler) http.Handler {
	return otelhttp.NewHandler(h, "http",
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return r.Method + " " + r.URL.Path
		}),
		// Health probes arrive every few seconds from the platform and the
		// uptime checks; they are not traced.
		otelhttp.WithFilter(func(r *http.Request) bool {
			return !isHealthProbe(r.URL.Path)
		}),
	)
}

// isHealthProbe reports whether path is a health route the platform and
// the uptime checks call: `/health`, `/healthz`, or a path ending in
// `/health`, `/health/live` or `/health/ready` under any prefix.
func isHealthProbe(path string) bool {
	switch {
	case path == "/health", path == "/healthz":
		return true
	case strings.HasSuffix(path, "/health"),
		strings.HasSuffix(path, "/health/live"),
		strings.HasSuffix(path, "/health/ready"):
		return true
	}
	return false
}

// NewHTTPClient returns an outbound HTTP client whose requests carry the
// active trace context (traceparent header) and appear as client spans —
// this is what stitches a service-api request to the adapter's server span,
// and the adapter's span to the carrier call, in one waterfall. For a client
// whose exchanges are also captured, see Capturer.Client.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: otelhttp.NewTransport(http.DefaultTransport),
	}
}

// NewHTTPClientWithRoots is NewHTTPClient verifying server certificates
// against roots instead of the system pool.
func NewHTTPClientWithRoots(timeout time.Duration, roots *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: otelhttp.NewTransport(transportWithRoots(roots)),
	}
}

// transportWithRoots clones the default transport with a custom root pool.
func transportWithRoots(roots *x509.CertPool) *http.Transport {
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	return base
}

// AccessLogMiddleware emits one canonical line per request — method, path,
// status, duration, the caller and the address they called from — through
// the context-aware logger, so the line carries the request id + trace
// correlation. It is the record of who reached which endpoint and when, for
// every request including the ones that authenticate no one. Health probes
// are skipped to keep the shared log readable.
//
// It also leaves the actor slot on the context, which the identity
// middleware fills once the caller is known (SetActorUserID,
// SetActorAPIKeyID) and the inbound capture reads.
func AccessLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isHealthProbe(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		ctx := withActor(r.Context())
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r.WithContext(ctx))
		level := slog.LevelInfo
		if rec.status >= http.StatusInternalServerError {
			level = slog.LevelError
		}
		args := []any{
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"durationMs", time.Since(start).Milliseconds(),
			"clientIp", ClientIP(r),
		}
		if userID := ActorUserID(ctx); userID != "" {
			args = append(args, "userId", userID)
		}
		if apiKeyID := ActorAPIKeyID(ctx); apiKeyID != "" {
			args = append(args, "apiKeyId", apiKeyID)
		}
		slog.Default().Log(ctx, level, "http request", args...)
	})
}

// ClientIP is the address the request came from: the first hop of
// X-Forwarded-For when a proxy (Cloud Run's front end, the load balancer)
// set it, otherwise the connection's remote address.
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// statusRecorder captures the response status for the access log. Flush is
// forwarded so streaming responses (the rating SSE stream) keep working
// through the wrapper, and Unwrap exposes the writer beneath it, so a
// handler's http.ResponseController reaches the connection — a stream or a
// long wait extends its write deadline through it.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

// RecoverMiddleware turns a handler panic into one ERROR record and a clean
// 500 envelope, instead of net/http's default (connection dropped, stack
// buried at INFO through the log-package bridge). The stack rides on the
// `stack_trace` attribute — the field Error Reporting recognizes, so panics
// group into tracked errors with first/last-seen and frequency.
//
// http.ErrAbortHandler re-panics untouched: it is net/http's sanctioned way
// to abort a response and must reach the server's own recover.
//
// A service with its own error envelope wraps the same way with its own
// writer; this one speaks the integration contract's envelope.
func RecoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			if rec == http.ErrAbortHandler { //nolint:errorlint // sentinel comparison per net/http docs
				panic(rec)
			}
			slog.ErrorContext(r.Context(), "panic recovered",
				"panic", rec,
				"method", r.Method,
				"path", r.URL.Path,
				"stack_trace", string(debug.Stack()),
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"status":500,"error":"upstream_error","message":"Integration service encountered an internal error."}`))
		}()
		next.ServeHTTP(w, r)
	})
}
