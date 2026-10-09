package obs

import "net/http"

// The tests reach the redaction rules through the library's own defaults.

func prepareBody(contentType string, raw []byte, limit int) bodyRecord {
	return defaultRules.prepareBody(contentType, raw, len(raw), captureLimit).cut(limit)
}

func redactHeaders(h http.Header) map[string]string {
	return defaultRules.redactHeaders(h)
}
