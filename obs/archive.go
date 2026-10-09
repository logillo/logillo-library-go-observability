package obs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"cloud.google.com/go/storage"
)

// The exchange archive keeps the calls that change something at a partner
// — a booking, a cancellation, a pickup — and the writes a client's
// integration makes to the platform, as files, for as long as a dispute can
// arise. Logs are for the weeks after; the archive is for the months.
//
// Each exchange is one JSON file holding exactly what the log holds — the
// request and the response with secrets blanked — under a name that starts
// with the request id, so a booking row, a log line and an archived file
// meet on the same id.

// Archive stores exchange records.
type Archive interface {
	// Store writes record under name and returns where it landed.
	Store(ctx context.Context, name string, record []byte) (location string, err error)
}

// ArchiveBucketEnv names the bucket the archive writes to. A service with
// the variable unset archives nothing.
const ArchiveBucketEnv = "EXCHANGE_ARCHIVE_BUCKET"

// NewArchiveFromEnv returns the archive the environment configures: a
// Cloud Storage bucket named by EXCHANGE_ARCHIVE_BUCKET, or NopArchive when
// it is unset. On an error the archive is nil: a service stops rather than
// run without the archive it was told to keep.
func NewArchiveFromEnv(ctx context.Context) (Archive, error) {
	bucket := strings.TrimSpace(os.Getenv(ArchiveBucketEnv))
	if bucket == "" {
		return NopArchive{}, nil
	}
	a, err := NewGCSArchive(ctx, bucket)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// NopArchive stores nothing and reports no location.
type NopArchive struct{}

func (NopArchive) Store(context.Context, string, []byte) (string, error) { return "", nil }

// GCSArchive stores records as objects in one Cloud Storage bucket. The
// writer needs only the right to create objects; reading the archive is a
// separate grant held by whoever investigates.
type GCSArchive struct {
	client *storage.Client
	bucket *storage.BucketHandle
	name   string
}

// NewGCSArchive opens the archive in bucket. A write that fails on the way
// is retried: an object's name is its content's, so a retry writes the
// same bytes again.
func NewGCSArchive(ctx context.Context, bucket string) (*GCSArchive, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("open storage client: %w", err)
	}
	handle := client.Bucket(bucket).Retryer(storage.WithPolicy(storage.RetryAlways))
	return &GCSArchive{client: client, bucket: handle, name: bucket}, nil
}

// Close releases the storage client.
func (a *GCSArchive) Close() error {
	return a.client.Close()
}

func (a *GCSArchive) Store(ctx context.Context, name string, record []byte) (string, error) {
	w := a.bucket.Object(name).NewWriter(ctx)
	w.ContentType = "application/json"
	// One record is one request: no resumable session, no chunk buffer.
	w.ChunkSize = 0
	if _, err := w.Write(record); err != nil {
		_ = w.Close()
		return "", fmt.Errorf("write archive object: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("close archive object: %w", err)
	}
	return "gs://" + a.name + "/" + name, nil
}

var unsafeObjectChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// archiveObjectName places a record under the peer, the day and the request
// id: `<peer>/<yyyy-mm-dd>/<request id>/<hhmmss.mmm>-<operation>-<hash>.json`.
// The hash is the record's own, so two exchanges of one request in the same
// millisecond — a batch booking's — never share a name. A record without a
// request id — a background job's — files under "no-request-id".
func archiveObjectName(peer, operation, requestID string, at time.Time, record []byte) string {
	if requestID == "" {
		requestID = "no-request-id"
	}
	requestID = unsafeObjectChars.ReplaceAllString(requestID, "-")
	peer = unsafeObjectChars.ReplaceAllString(strings.ToLower(peer), "-")
	operation = unsafeObjectChars.ReplaceAllString(strings.ToLower(operation), "-")
	if operation == "" || operation == "-" {
		operation = "exchange"
	}
	at = at.UTC()
	sum := sha256.Sum256(record)
	return fmt.Sprintf("%s/%s/%s/%s-%s-%s.json", peer, at.Format("2006-01-02"), requestID, at.Format("150405.000"), operation, hex.EncodeToString(sum[:3]))
}
