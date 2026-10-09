package obs

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

// RequestIDHeader is the name of the request id header on the wire. A
// client may supply one on an inbound request; service-api forwards its own
// to every adapter it calls; every response echoes it. One id therefore
// names a request across every service it touches, and every log line each
// of them writes carries it.
const RequestIDHeader = "X-Request-ID"

type requestIDKey struct{}

// RequestIDMiddleware ensures every request carries a request id in its
// context and echoes it on the response. Wire it before any middleware or
// handler that logs or answers.
//
// An inbound header is honoured only when it parses as a UUID: an arbitrary
// client-supplied string would be written into every log line of the request
// and is refused in favour of a fresh id.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := resolveRequestID(r.Header.Get(RequestIDHeader))
		w.Header().Set(RequestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(WithRequestID(r.Context(), id)))
	})
}

// WithRequestID returns a context carrying id as the request id.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestID returns the request id stored in ctx, or "" outside a request —
// a background job that did not inherit one.
func RequestID(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey{}).(string); ok {
		return v
	}
	return ""
}

// RequestIDOrNew returns the request id from ctx, minting one when ctx has
// none, for code that must name a request before or outside the middleware.
func RequestIDOrNew(ctx context.Context) string {
	if id := RequestID(ctx); id != "" {
		return id
	}
	return NewRequestID()
}

// NewRequestID mints a request id: a UUID v7, sortable by time, like the
// platform's entity ids.
func NewRequestID() string {
	id, err := uuid.NewV7()
	if err != nil {
		// NewV7 fails only on RNG exhaustion; a v4 keeps the id parseable.
		return uuid.NewString()
	}
	return id.String()
}

// resolveRequestID keeps a supplied id that parses as a UUID, in the
// canonical spelling, and mints one otherwise.
func resolveRequestID(supplied string) string {
	if supplied != "" {
		if id, err := uuid.Parse(supplied); err == nil {
			return id.String()
		}
	}
	return NewRequestID()
}
