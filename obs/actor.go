package obs

import (
	"context"
	"sync"
)

// The access log wraps the whole router, above authentication, so that a
// request which never resolves a caller — a rejected token, an unknown
// route — still produces a line. That position also means it cannot read
// the principal from the context its handlers see: authentication derives
// its own context further down the chain. actor is the slot the access log
// leaves behind for the identity middleware to fill in once the caller is
// known. The inbound capture reads the same slot to decide what to keep.
type actor struct {
	mu       sync.Mutex
	userID   string
	apiKeyID string
}

type actorKey struct{}

func withActor(ctx context.Context) context.Context {
	if _, ok := ctx.Value(actorKey{}).(*actor); ok {
		return ctx
	}
	return context.WithValue(ctx, actorKey{}, &actor{})
}

// SetActorUserID records the authenticated caller of the request, so the
// access log can name whoever made it. Requests that authenticate no one
// leave it unset.
func SetActorUserID(ctx context.Context, userID string) {
	if userID == "" {
		return
	}
	a, ok := ctx.Value(actorKey{}).(*actor)
	if !ok {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.userID = userID
}

// ActorUserID returns the user recorded with SetActorUserID, or "".
func ActorUserID(ctx context.Context) string {
	a, ok := ctx.Value(actorKey{}).(*actor)
	if !ok {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.userID
}

// SetActorAPIKeyID records the API key a request authenticated with, so the
// access log names the integration behind it and not only the user it
// belongs to. Signed-in sessions leave it unset.
func SetActorAPIKeyID(ctx context.Context, apiKeyID string) {
	if apiKeyID == "" {
		return
	}
	a, ok := ctx.Value(actorKey{}).(*actor)
	if !ok {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.apiKeyID = apiKeyID
}

// ActorAPIKeyID returns the API key recorded with SetActorAPIKeyID, or "".
func ActorAPIKeyID(ctx context.Context) string {
	a, ok := ctx.Value(actorKey{}).(*actor)
	if !ok {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.apiKeyID
}
