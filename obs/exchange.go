package obs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"
)

// A Capturer records HTTP exchanges at a service boundary as "exchange"
// log records — the request and the response in full, secrets blanked,
// files reduced to size and fingerprint — and, when asked, as files in the
// exchange archive.
//
// Outbound: Transport wraps the round tripper of an HTTP client, so every
// call the client makes is captured without the calling code doing
// anything. Inbound: Inbound is a middleware that captures the requests a
// service decides to keep.
//
// Every record carries `capture: "exchange"`, the field the log router keys
// on to file these records in their own bucket, with their own retention and
// their own readers.
type Capturer struct {
	peer             string
	archive          Archive
	bodyLimit        int
	rules            *rules
	volatile         map[string]bool
	changes          *changeTracker
	peerOf           func(*http.Request) string
	opOf             func(*http.Request) string
	archiveWhen      func(*http.Request) bool
	changeKeyOf      func(*http.Request) string
	forwardRequestID bool
	now              func() time.Time
}

// CapturerOption configures a Capturer.
type CapturerOption func(*Capturer)

// ArchiveTo stores the exchanges marked with WithArchiving in a. A nil
// archive, typed or not, keeps NopArchive.
func ArchiveTo(a Archive) CapturerOption {
	return func(c *Capturer) {
		if a == nil {
			return
		}
		if v := reflect.ValueOf(a); v.Kind() == reflect.Pointer && v.IsNil() {
			return
		}
		c.archive = a
	}
}

// BodyLimit caps one captured body on the log line at n bytes; a larger
// body is cut there and marked, while the archive keeps it whole up to
// 2 MiB. The default is 64 KiB.
func BodyLimit(n int) CapturerOption {
	return func(c *Capturer) {
		if n > 0 {
			c.bodyLimit = n
		}
	}
}

// SensitiveFields adds a rule for a peer whose secrets travel under names
// no generic rule can know: f reports whether the field name under parent
// is a secret, and its value is written as "<redacted>". An account number
// carried as the `id` of a party is the shape this exists for.
func SensitiveFields(f func(parent, name string) bool) CapturerOption {
	return func(c *Capturer) {
		if f != nil {
			c.rules = &rules{sensitive: f}
		}
	}
}

// VolatileFields names the JSON fields a repeated answer carries that
// change on every call without meaning a change — a per-call transaction
// id, a timestamp — so a change-keyed poll is compared without them.
func VolatileFields(names ...string) CapturerOption {
	return func(c *Capturer) {
		for _, n := range names {
			c.volatile[strings.ToLower(n)] = true
		}
	}
}

// PeerFromRequest names the far side per request, for a client that talks
// to several — service-api's adapter client, which reaches every carrier
// adapter through one client. A call whose context names a peer with
// WithPeer takes precedence; a call this function names "" falls back to
// the Capturer's own peer, then to the request host.
func PeerFromRequest(f func(*http.Request) string) CapturerOption {
	return func(c *Capturer) { c.peerOf = f }
}

// OperationFromRequest names the operation per request — "booking.create",
// "tracking" — when the calling code does not name it with WithOperation.
func OperationFromRequest(f func(*http.Request) string) CapturerOption {
	return func(c *Capturer) { c.opOf = f }
}

// ArchiveWhen archives every call f approves, in addition to the calls
// whose context asks with WithArchiving — one rule for a client whose
// archived operations are told apart by path.
func ArchiveWhen(f func(*http.Request) bool) CapturerOption {
	return func(c *Capturer) { c.archiveWhen = f }
}

// ChangeKeyFromRequest derives the change key per request — the tracking
// number in a tracking call's path — for calls whose context does not set
// one with WithChangeKey. An empty key captures the call in full.
func ChangeKeyFromRequest(f func(*http.Request) string) CapturerOption {
	return func(c *Capturer) { c.changeKeyOf = f }
}

// ForwardRequestID sends the request id of the calling context onward as
// X-Request-ID on every call that carries none, so a service's call to
// another Logillo service shares one id end to end. A client that talks to
// an outside party leaves it off: our ids are nothing to a carrier.
func ForwardRequestID() CapturerOption {
	return func(c *Capturer) { c.forwardRequestID = true }
}

// NewCapturer returns a Capturer for exchanges with peer: a carrier's name
// for an adapter, "api" for the platform's inbound API, "adapter" for
// service-api's calls to adapters (named per request with PeerFromRequest).
func NewCapturer(peer string, opts ...CapturerOption) *Capturer {
	c := &Capturer{
		peer:      peer,
		archive:   NopArchive{},
		bodyLimit: defaultBodyLimit,
		rules:     defaultRules,
		volatile:  map[string]bool{},
		changes:   newChangeTracker(20000),
		now:       time.Now,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Per-call controls, carried on the request context.

type peerCtxKey struct{}
type operationCtxKey struct{}
type changeKeyCtxKey struct{}
type archivingCtxKey struct{}

// WithPeer names the far side of the calls made with ctx.
func WithPeer(ctx context.Context, peer string) context.Context {
	return context.WithValue(ctx, peerCtxKey{}, peer)
}

// WithOperation names what the calls made with ctx do — "booking.create",
// "pickup.cancel", "tracking" — so an exchange can be found by what it was
// for, and the archive files it under that name.
func WithOperation(ctx context.Context, operation string) context.Context {
	return context.WithValue(ctx, operationCtxKey{}, operation)
}

// WithChangeKey marks the calls made with ctx as repeated: the answer is
// captured in full only when it differs from the last answer recorded for
// key — a tracking poll every half hour writes its bodies once per change,
// and a DEBUG line with no bodies the rest of the time.
func WithChangeKey(ctx context.Context, key string) context.Context {
	return context.WithValue(ctx, changeKeyCtxKey{}, key)
}

// WithArchiving marks the calls made with ctx for the exchange archive:
// calls that change something at a partner, kept for as long as a dispute
// can arise.
func WithArchiving(ctx context.Context) context.Context {
	return context.WithValue(ctx, archivingCtxKey{}, true)
}

func ctxString(ctx context.Context, key any) string {
	v, _ := ctx.Value(key).(string)
	return v
}

func archiving(ctx context.Context) bool {
	v, _ := ctx.Value(archivingCtxKey{}).(bool)
	return v
}

func (c *Capturer) shouldArchive(ctx context.Context, r *http.Request) bool {
	if archiving(ctx) {
		return true
	}
	return c.archiveWhen != nil && c.archiveWhen(r)
}

func (c *Capturer) resolveChangeKey(ctx context.Context, r *http.Request) string {
	if key := ctxString(ctx, changeKeyCtxKey{}); key != "" {
		return key
	}
	if c.changeKeyOf != nil {
		return c.changeKeyOf(r)
	}
	return ""
}

// InheritRequestContext carries what identifies a request — its id, the
// keys bound to its log lines, the actor, the trace — from src onto dst,
// for work that outlives the request on a context of its own: a rating run
// started in a goroutine, a booking finishing after the client stopped
// waiting. The cancellation and deadline of dst stay dst's.
func InheritRequestContext(dst, src context.Context) context.Context {
	if id := RequestID(src); id != "" {
		dst = WithRequestID(dst, id)
	}
	if attrs := contextAttrs(src); len(attrs) > 0 {
		dst = ContextWithAttrs(dst, attrs...)
	}
	if a, ok := src.Value(actorKey{}).(*actor); ok {
		dst = context.WithValue(dst, actorKey{}, a)
	}
	if sc := trace.SpanContextFromContext(src); sc.IsValid() {
		dst = trace.ContextWithSpanContext(dst, sc)
	}
	return dst
}

// exchangeSide is one side of an exchange: the headers and the body.
type exchangeSide struct {
	Headers map[string]string `json:"headers,omitempty"`
	bodyRecord
}

// cut returns the side with its body cut at limit for a log line.
func (s *exchangeSide) cut(limit int) *exchangeSide {
	if s == nil {
		return nil
	}
	c := *s
	c.bodyRecord = s.bodyRecord.cut(limit)
	return &c
}

// exchangeRecord is what is logged and archived for one exchange. The log
// line carries these as flat attributes beside the request id and the
// business keys bound on the context; the archive file carries them all
// together, so it reads on its own.
type exchangeRecord struct {
	Capture    string            `json:"capture"`
	Direction  string            `json:"direction"`
	Peer       string            `json:"peer"`
	Operation  string            `json:"operation,omitempty"`
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	Status     int               `json:"status,omitempty"`
	DurationMs int64             `json:"durationMs"`
	Error      string            `json:"error,omitempty"`
	Request    exchangeSide      `json:"request"`
	Response   *exchangeSide     `json:"response,omitempty"`
	Unchanged  bool              `json:"unchanged,omitempty"`
	ChangeKey  string            `json:"changeKey,omitempty"`
	At         time.Time         `json:"at"`
	RequestID  string            `json:"requestId,omitempty"`
	Attributes map[string]any    `json:"attributes,omitempty"`
	Actor      map[string]string `json:"actor,omitempty"`
	Archived   string            `json:"archived,omitempty"`
}

func (c *Capturer) resolvePeer(ctx context.Context, r *http.Request) string {
	if p := ctxString(ctx, peerCtxKey{}); p != "" {
		return p
	}
	if c.peerOf != nil {
		if p := c.peerOf(r); p != "" {
			return p
		}
	}
	if c.peer != "" {
		return c.peer
	}
	if r != nil && r.URL != nil {
		return r.URL.Host
	}
	return "unknown"
}

func (c *Capturer) resolveOperation(ctx context.Context, r *http.Request) string {
	if op := ctxString(ctx, operationCtxKey{}); op != "" {
		return op
	}
	if c.opOf != nil {
		return c.opOf(r)
	}
	return ""
}

// archiveTimeout bounds the archive write of one exchange. The write runs
// on a context of its own: the request's may already be cancelled — a
// client that stopped waiting for its booking — and that exchange is the
// one a dispute turns on.
const archiveTimeout = 10 * time.Second

// emit writes the record as a log line and, when asked, as an archive file.
// The archive is written first so the log line can point at the file, and
// holds the record whole; the log line holds the bodies cut at the body
// limit.
func (c *Capturer) emit(ctx context.Context, rec *exchangeRecord, archive bool) {
	rec.Capture = "exchange"
	rec.RequestID = RequestID(ctx)
	if attrs := contextAttrs(ctx); len(attrs) > 0 {
		rec.Attributes = make(map[string]any, len(attrs))
		for _, a := range attrs {
			rec.Attributes[a.Key] = a.Value.Any()
		}
	}
	if user, key := ActorUserID(ctx), ActorAPIKeyID(ctx); user != "" || key != "" {
		rec.Actor = map[string]string{}
		if user != "" {
			rec.Actor["userId"] = user
		}
		if key != "" {
			rec.Actor["apiKeyId"] = key
		}
	}

	var archiveErr error
	if archive {
		if encoded, err := json.Marshal(rec); err != nil {
			archiveErr = err
		} else {
			storeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), archiveTimeout)
			location, err := c.archive.Store(storeCtx, archiveObjectName(rec.Peer, rec.Operation, rec.RequestID, rec.At, encoded), encoded)
			cancel()
			if err != nil {
				archiveErr = err
			} else {
				rec.Archived = location
			}
		}
	}

	attrs := []slog.Attr{
		slog.String("capture", rec.Capture),
		slog.String("direction", rec.Direction),
		slog.String("peer", rec.Peer),
		slog.String("method", rec.Method),
		slog.String("url", rec.URL),
		slog.Int64("durationMs", rec.DurationMs),
	}
	if rec.Operation != "" {
		attrs = append(attrs, slog.String("operation", rec.Operation))
	}
	if rec.Status != 0 {
		attrs = append(attrs, slog.Int("status", rec.Status))
	}
	if rec.Error != "" {
		attrs = append(attrs, slog.String("error", rec.Error))
	}
	attrs = append(attrs, slog.Any("request", rec.Request.cut(c.bodyLimit)))
	if rec.Response != nil {
		attrs = append(attrs, slog.Any("response", rec.Response.cut(c.bodyLimit)))
	}
	if rec.Actor != nil {
		attrs = append(attrs, slog.Any("actor", rec.Actor))
	}
	if rec.ChangeKey != "" {
		attrs = append(attrs, slog.String("changeKey", rec.ChangeKey))
	}
	if rec.Unchanged {
		attrs = append(attrs, slog.Bool("unchanged", true))
	}
	if rec.Archived != "" {
		attrs = append(attrs, slog.String("archived", rec.Archived))
	}
	if archiveErr != nil {
		attrs = append(attrs, slog.String("archiveError", archiveErr.Error()))
	}

	level := slog.LevelInfo
	switch {
	case rec.Error != "" || rec.Status >= http.StatusInternalServerError:
		level = slog.LevelWarn
	case rec.Unchanged:
		level = slog.LevelDebug
	}
	slog.Default().LogAttrs(ctx, level, "exchange", attrs...)

	if archiveErr != nil {
		slog.WarnContext(ctx, "exchange archive failed",
			"peer", rec.Peer, "operation", rec.Operation, "error", archiveErr.Error(), "swallowed", true)
	}
}

// Transport returns a round tripper that captures every exchange made
// through it before handing the call to base. Wrap base in OTel first so the
// captured request shows what the application sent and the trace still
// covers the call: Transport(otelhttp.NewTransport(http.DefaultTransport)).
func (c *Capturer) Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &captureTransport{c: c, base: base}
}

// Client returns an HTTP client whose calls are traced and captured. A
// zero timeout is no timeout.
func (c *Capturer) Client(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: c.Transport(otelhttp.NewTransport(http.DefaultTransport)),
	}
}

// ClientWithRoots is Client verifying server certificates against roots.
func (c *Capturer) ClientWithRoots(timeout time.Duration, roots *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: c.Transport(otelhttp.NewTransport(transportWithRoots(roots))),
	}
}

type captureTransport struct {
	c    *Capturer
	base http.RoundTripper
}

func (t *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	start := t.c.now()

	// The request goes out as a copy: the body is read once here and handed
	// to the base transport again from memory, so the capture and the call
	// see the same bytes, and the request id joins the headers when asked.
	sent := req.Clone(ctx)
	var reqBody []byte
	if req.Body != nil && req.Body != http.NoBody {
		b, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read request body for capture: %w", err)
		}
		reqBody = b
		sent.Body = io.NopCloser(bytes.NewReader(b))
		sent.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
		sent.ContentLength = int64(len(b))
	}
	if t.c.forwardRequestID && sent.Header.Get(RequestIDHeader) == "" {
		if id := RequestID(ctx); id != "" {
			sent.Header.Set(RequestIDHeader, id)
		}
	}

	rules := t.c.rules
	rec := &exchangeRecord{
		Direction: "outbound",
		Peer:      t.c.resolvePeer(ctx, req),
		Operation: t.c.resolveOperation(ctx, req),
		Method:    req.Method,
		URL:       redactURL(req.URL),
		At:        start,
		Request: exchangeSide{
			Headers:    rules.redactHeaders(sent.Header),
			bodyRecord: rules.prepareBody(sent.Header.Get("Content-Type"), reqBody, len(reqBody), captureLimit),
		},
	}
	archive := t.c.shouldArchive(ctx, req)

	resp, err := t.base.RoundTrip(sent)
	rec.DurationMs = t.c.now().Sub(start).Milliseconds()
	if err != nil {
		rec.Error = ErrorText(err)
		t.c.emit(ctx, rec, archive)
		return nil, err
	}

	var respBody []byte
	if resp.Body != nil {
		b, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			rec.Status = resp.StatusCode
			rec.Error = "read response body: " + ErrorText(readErr)
			t.c.emit(ctx, rec, archive)
			return nil, fmt.Errorf("read response body: %w", readErr)
		}
		respBody = b
		resp.Body = io.NopCloser(bytes.NewReader(b))
	}
	rec.DurationMs = t.c.now().Sub(start).Milliseconds()
	rec.Status = resp.StatusCode
	rec.Response = &exchangeSide{
		Headers: rules.redactHeaders(resp.Header),
		bodyRecord: bodyRecord{
			Bytes:       len(respBody),
			ContentType: mediaTypeOf(resp.Header.Get("Content-Type")),
		},
	}

	// A repeated answer is compared before it is prepared: an unchanged
	// poll costs a hash, not a parse.
	if key := t.c.resolveChangeKey(ctx, req); key != "" {
		rec.ChangeKey = key
		if t.c.changes.unchanged(key, t.c.changeDigest(respBody)) {
			rec.Unchanged = true
			rec.Request.Body = nil
			t.c.emit(ctx, rec, archive)
			return resp, nil
		}
	}
	rec.Response.bodyRecord = rules.prepareBody(resp.Header.Get("Content-Type"), respBody, len(respBody), captureLimit)

	t.c.emit(ctx, rec, archive)
	return resp, nil
}

// mediaTypeOf is the media type of a Content-Type header, without
// parameters.
func mediaTypeOf(contentType string) string {
	if mt, _, err := mime.ParseMediaType(contentType); err == nil {
		return mt
	}
	return contentType
}

// changeDigest hashes an answer for the change tracker. With volatile
// fields named, a JSON answer is hashed without them, so a per-call
// transaction id does not read as a change.
func (c *Capturer) changeDigest(body []byte) [sha256.Size]byte {
	if len(c.volatile) == 0 || !looksLikeJSON(body) {
		return sha256.Sum256(body)
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return sha256.Sum256(body)
	}
	stable, err := json.Marshal(dropFields(v, c.volatile))
	if err != nil {
		return sha256.Sum256(body)
	}
	return sha256.Sum256(stable)
}

// dropFields removes the named fields, at any depth, from parsed JSON.
func dropFields(v any, names map[string]bool) any {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if names[strings.ToLower(k)] {
				delete(t, k)
				continue
			}
			t[k] = dropFields(child, names)
		}
		return t
	case []any:
		for i, child := range t {
			t[i] = dropFields(child, names)
		}
		return t
	default:
		return v
	}
}

// InboundDecision is a service's answer to "keep this request?", given
// once the response is written.
type InboundDecision struct {
	// Log writes the exchange record.
	Log bool
	// Archive also stores the exchange in the archive.
	Archive bool
	// Operation names the exchange; "" means the method and path.
	Operation string
}

// Inbound returns a middleware that captures the requests decide keeps.
// decide runs after the handler, with the response status, so it can read
// what the request turned out to be: the actor the identity middleware
// recorded (ActorAPIKeyID, ActorUserID), the method, the route.
//
// Mount it on the router, inside AccessLogMiddleware, so the route the
// request matched is known when decide runs. The request body is read as
// the handler reads it, never ahead of it; what the record keeps of it is
// its first 2 MiB. Streaming responses are recorded by size, never
// buffered.
func (c *Capturer) Inbound(decide func(r *http.Request, status int) InboundDecision) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isHealthProbe(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			ctx := withActor(r.Context())
			start := c.now()

			var body *prefixReader
			if r.Body != nil && r.Body != http.NoBody {
				body = &prefixReader{ReadCloser: r.Body, limit: captureLimit}
				r.Body = body
			}

			rec := &captureWriter{ResponseWriter: w, status: http.StatusOK, limit: captureLimit}
			next.ServeHTTP(rec, r.WithContext(ctx))

			d := decide(r.WithContext(ctx), rec.status)
			if !d.Log && !d.Archive {
				return
			}
			operation := d.Operation
			if operation == "" {
				operation = r.Method + " " + r.URL.Path
			}
			var reqBody []byte
			reqTotal := 0
			if body != nil {
				reqBody, reqTotal = body.captured()
			}
			record := &exchangeRecord{
				Direction:  "inbound",
				Peer:       c.resolvePeer(ctx, r),
				Operation:  operation,
				Method:     r.Method,
				URL:        redactURL(r.URL),
				Status:     rec.status,
				DurationMs: c.now().Sub(start).Milliseconds(),
				At:         start,
				Request: exchangeSide{
					Headers:    c.rules.redactHeaders(r.Header),
					bodyRecord: c.rules.prepareBody(r.Header.Get("Content-Type"), reqBody, reqTotal, captureLimit),
				},
				Response: &exchangeSide{
					Headers:    c.rules.redactHeaders(rec.Header()),
					bodyRecord: rec.record(c.rules),
				},
			}
			c.emit(ctx, record, d.Archive)
		})
	}
}

// prefixReader hands a request body to the handler as it reads it and
// keeps the first limit bytes for the record, so the capture never holds
// more of a body than that, nor reads ahead of the handler.
type prefixReader struct {
	io.ReadCloser
	limit int
	mu    sync.Mutex
	buf   bytes.Buffer
	total int
}

func (p *prefixReader) Read(b []byte) (int, error) {
	n, err := p.ReadCloser.Read(b)
	if n > 0 {
		p.mu.Lock()
		p.total += n
		if room := p.limit - p.buf.Len(); room > 0 {
			if n > room {
				p.buf.Write(b[:room])
			} else {
				p.buf.Write(b[:n])
			}
		}
		p.mu.Unlock()
	}
	return n, err
}

// captured returns the prefix kept and the bytes read in all.
func (p *prefixReader) captured() ([]byte, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.buf.Bytes(), p.total
}

// captureWriter records the status and body of a response as the handler
// writes it. A streaming response (text/event-stream) is recorded by size
// only, so a stream that stays open for minutes buffers nothing. Flush and
// Unwrap are forwarded as statusRecorder does.
type captureWriter struct {
	http.ResponseWriter
	status   int
	wrote    bool
	streamed bool
	bytes    int
	buf      bytes.Buffer
	limit    int
	once     sync.Once
}

func (w *captureWriter) WriteHeader(status int) {
	w.status = status
	w.once.Do(w.detectStream)
	w.ResponseWriter.WriteHeader(status)
}

func (w *captureWriter) detectStream() {
	ct := strings.ToLower(w.ResponseWriter.Header().Get("Content-Type"))
	w.streamed = strings.HasPrefix(ct, "text/event-stream")
}

func (w *captureWriter) Write(p []byte) (int, error) {
	w.once.Do(w.detectStream)
	w.wrote = true
	w.bytes += len(p)
	if !w.streamed {
		if room := w.limit - w.buf.Len(); room > 0 {
			if len(p) > room {
				w.buf.Write(p[:room])
			} else {
				w.buf.Write(p)
			}
		}
	}
	return w.ResponseWriter.Write(p)
}

func (w *captureWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *captureWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// record is the response body as captured.
func (w *captureWriter) record(r *rules) bodyRecord {
	ct := w.ResponseWriter.Header().Get("Content-Type")
	if w.streamed {
		return bodyRecord{Body: "<stream>", Bytes: w.bytes, ContentType: "text/event-stream"}
	}
	return r.prepareBody(ct, w.buf.Bytes(), w.bytes, captureLimit)
}
