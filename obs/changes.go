package obs

import (
	"container/list"
	"crypto/sha256"
	"sync"
)

// changeTracker remembers the last answer seen for a key, so a call that is
// repeated until something changes — a tracking poll every half hour — is
// captured in full only when the answer differs from the one before.
//
// It lives in process memory and is bounded: the least recently seen keys
// make room for new ones. A restarted instance captures each key's next
// answer once more, which is the price of keeping nothing durable here.
type changeTracker struct {
	mu    sync.Mutex
	max   int
	order *list.List
	byKey map[string]*list.Element
}

type changeEntry struct {
	key  string
	hash [sha256.Size]byte
}

func newChangeTracker(max int) *changeTracker {
	return &changeTracker{max: max, order: list.New(), byKey: make(map[string]*list.Element)}
}

// unchanged records the answer for key and reports whether it matches the
// answer recorded before.
func (t *changeTracker) unchanged(key string, body []byte) bool {
	hash := sha256.Sum256(body)
	t.mu.Lock()
	defer t.mu.Unlock()
	if el, ok := t.byKey[key]; ok {
		entry := el.Value.(*changeEntry)
		same := entry.hash == hash
		entry.hash = hash
		t.order.MoveToFront(el)
		return same
	}
	t.byKey[key] = t.order.PushFront(&changeEntry{key: key, hash: hash})
	for t.order.Len() > t.max {
		oldest := t.order.Back()
		t.order.Remove(oldest)
		delete(t.byKey, oldest.Value.(*changeEntry).key)
	}
	return false
}
