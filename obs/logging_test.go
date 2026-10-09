package obs

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
)

// A record for Cloud Logging carries its level as `severity` and its text
// as `message` — the fields the log-based alerts filter on — and the
// request id of its context.
func TestCloudLoggingRecordsCarrySeverityMessageAndRequestID(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(&ctxHandler{inner: slog.NewJSONHandler(&buf, &slog.HandlerOptions{ReplaceAttr: replaceForCloudLogging})})
	logger.WarnContext(WithRequestID(context.Background(), "req-1"), "carrier answered late", "carrierId", "c-1")
	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatal(err)
	}
	if line["severity"] != "WARNING" || line["message"] != "carrier answered late" || line["requestId"] != "req-1" || line["carrierId"] != "c-1" {
		t.Errorf("line = %v", line)
	}
	if _, has := line["level"]; has {
		t.Error("level must be written as severity")
	}
	if _, has := line["msg"]; has {
		t.Error("msg must be written as message")
	}
	for level, want := range map[slog.Level]string{slog.LevelDebug: "DEBUG", slog.LevelInfo: "INFO", slog.LevelWarn: "WARNING", slog.LevelError: "ERROR"} {
		if got := severityFor(level); got != want {
			t.Errorf("severity for %v = %s", level, got)
		}
	}
}
