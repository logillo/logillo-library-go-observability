package obs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// What a captured exchange may never contain, and what it carries in place
// of what it drops:
//
//   - A secret — a key, a password, a token, a signature — is written as
//     "<redacted>", wherever it sits: a header, a query parameter, a JSON
//     field, a form field, an XML element or a `name=value` pair in text.
//     Field names decide, matched case-insensitively against the list
//     below; a value is never inspected to guess whether it is a secret.
//   - A file — a label, a PDF, an image, anything base64 — is written as
//     its size and SHA-256, so a dispute can still prove which bytes were
//     exchanged without the bytes filling the log.
//   - A body past the size limit is cut at the limit and marked.
//
// Over-redaction hides a field from a debugging log; under-redaction leaks
// a carrier's key. The rules below lean towards the first.

const (
	redacted = "<redacted>"

	// defaultBodyLimit caps one captured body. Cloud Logging accepts 256 KiB
	// per entry; a request and a response at this limit plus headers fit.
	defaultBodyLimit = 100 << 10

	// fileThreshold is the length from which a base64 string is treated as
	// file content rather than a value worth reading.
	fileThreshold = 1024

	// longStringThreshold is the length from which any string is treated as
	// content — a ZPL label, a document — and fingerprinted.
	longStringThreshold = 32 << 10
)

// sensitiveFragments mark a header, parameter or field as a secret when its
// name contains one of them: the names credentials travel under at the
// platform's boundaries — Authorization and X-Carrier-Credentials on the
// platform side; at the peers an API key header, a customer key, an OAuth
// client id, secret and access token, a login password, a request
// signature. A carrier account number is not a credential but is billed
// against, so it stays out of the logs too — under its own name, and as the
// `number` of an account object (`accounts[].number`).
// An idempotency key is sensitive by the integration idempotency standard.
var sensitiveFragments = []string{
	"password", "passwd", "secret", "token", "credential", "apikey", "api_key", "api-key",
	"authorization", "signature", "subscription-key", "subscription_key", "subscriptionkey",
	"cookie", "accountnumber", "account_number", "account-number",
	"client_id", "clientid", "idempotency",
}

// sensitiveExact are whole names that are secrets but match no fragment: a
// login's `pass` or `pwd`, a SOAP `session` ticket, an `eid` login object
// (an electronic-identity user name and password).
var sensitiveExact = map[string]bool{
	"pass": true, "pwd": true, "session": true, "eid": true,
}

// keyNameAllowed are names ending in "key" that identify, not authenticate.
var keyNameAllowed = map[string]bool{
	"primarykey": true, "sortkey": true, "partitionkey": true, "cachekey": true,
	"routingkey": true, "changekey": true, "mapkey": true, "foreignkey": true,
	"publickey": true, "keyboard": true,
}

// fileNameFragments mark a field as file content by name — a label, a
// document, an image — whatever its length, so a short ZPL label is treated
// like a long PDF.
var fileNameFragments = []string{"base64", "zpl", "pdf", "encodedlabel", "labelimage", "labeldata", "imagedata", "file_pdf"}

// contentThreshold is the length from which a field named `content` is
// file content rather than a note.
const contentThreshold = 256

// sensitiveName reports whether a header, parameter or field name denotes
// a secret.
func sensitiveName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	if sensitiveExact[n] {
		return true
	}
	for _, f := range sensitiveFragments {
		if strings.Contains(n, f) {
			return true
		}
	}
	// A name whose last word is "key" is a credential unless it is a known
	// identifier — customerKey, client_key, X-Account-Key all authenticate.
	// The word boundary matters: "monkey" is not a key.
	if endsInKeyWord(name) && !keyNameAllowed[n] {
		return true
	}
	return false
}

func endsInKeyWord(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	switch {
	case n == "key", strings.HasSuffix(n, "_key"), strings.HasSuffix(n, "-key"), strings.HasSuffix(n, ".key"):
		return true
	}
	// camelCase: a capital K starts the last word.
	return strings.HasSuffix(strings.TrimSpace(name), "Key")
}

// redactHeaders returns the headers with secret values blanked, each header
// as one string (multiple values joined).
func redactHeaders(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for name, values := range h {
		if sensitiveName(name) {
			out[name] = redacted
			continue
		}
		out[name] = strings.Join(values, ", ")
	}
	return out
}

// redactURL returns the URL with secret query parameters blanked. User
// info in the URL is dropped outright.
func redactURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	c := *u
	c.User = nil
	if c.RawQuery != "" {
		q := c.Query()
		changed := false
		for name := range q {
			if sensitiveName(name) {
				q[name] = []string{redacted}
				changed = true
			}
		}
		if changed {
			c.RawQuery = q.Encode()
		}
	}
	return c.String()
}

// fileRecord stands in for file content: how many bytes, and their hash.
type fileRecord struct {
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
}

func fingerprint(b []byte) fileRecord {
	sum := sha256.Sum256(b)
	return fileRecord{Bytes: len(b), SHA256: hex.EncodeToString(sum[:])}
}

// bodyRecord is a captured body as it is logged and archived.
type bodyRecord struct {
	// Body is the content: parsed JSON with secrets blanked and files
	// replaced, a text string, a file record, or nil for an empty body.
	Body any `json:"body,omitempty"`
	// Bytes is the size of the body as exchanged, before any reduction.
	Bytes int `json:"bytes"`
	// Truncated marks a body cut at the limit.
	Truncated bool `json:"truncated,omitempty"`
	// ContentType is the declared media type, without parameters.
	ContentType string `json:"contentType,omitempty"`
}

// prepareBody turns raw body bytes into what is logged: redacted, files
// fingerprinted, cut at limit.
func prepareBody(contentType string, raw []byte, limit int) bodyRecord {
	if limit <= 0 {
		limit = defaultBodyLimit
	}
	mediaType := contentType
	if mt, _, err := mime.ParseMediaType(contentType); err == nil {
		mediaType = mt
	}
	rec := bodyRecord{Bytes: len(raw), ContentType: mediaType}
	if len(raw) == 0 {
		return rec
	}

	if isBinaryMediaType(mediaType) {
		rec.Body = map[string]any{"$file": fingerprint(raw)}
		return rec
	}

	if looksLikeJSON(raw) {
		var v any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&v); err == nil {
			v = unwrapEncodedJSON(v)
			v = redactValue(v, "")
			encoded, err := json.Marshal(v)
			if err == nil {
				if len(encoded) > limit {
					rec.Body = string(encoded[:limit]) + "…"
					rec.Truncated = true
					return rec
				}
				rec.Body = v
				return rec
			}
		}
	}

	text := redactText(string(raw))
	if len(text) > limit {
		text = text[:limit] + "…"
		rec.Truncated = true
	}
	rec.Body = text
	return rec
}

// looksLikeJSON reports whether a body is a JSON object or array, directly
// or encoded as one JSON string (`"{\"…`).
func looksLikeJSON(raw []byte) bool {
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	if len(trimmed) > 1 && trimmed[0] == '"' {
		trimmed = trimmed[1:]
	}
	return len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')
}

func isBinaryMediaType(mediaType string) bool {
	mt := strings.ToLower(mediaType)
	switch {
	case strings.HasPrefix(mt, "image/"),
		strings.HasPrefix(mt, "audio/"),
		strings.HasPrefix(mt, "video/"),
		strings.HasPrefix(mt, "font/"),
		strings.HasPrefix(mt, "multipart/"):
		return true
	}
	switch mt {
	case "application/pdf", "application/octet-stream", "application/zip", "application/gzip",
		"application/x-zpl", "application/vnd.ms-excel",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
		return true
	}
	return false
}

// redactValue walks parsed JSON: secret fields are blanked by name, file
// content is replaced by its fingerprint. key is the field the value sits
// under — "" at the root; an array's elements sit under the array's own
// field, so a list of labels is a list of files.
func redactValue(v any, key string) any {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if sensitiveName(k) || accountNumberField(key, k) {
				t[k] = redacted
				continue
			}
			t[k] = redactValue(child, k)
		}
		return t
	case []any:
		for i, child := range t {
			t[i] = redactValue(child, key)
		}
		return t
	case string:
		if isFileField(key, t) || len(t) >= longStringThreshold || (len(t) >= fileThreshold && looksLikeBase64(t)) {
			return map[string]any{"$file": fingerprint([]byte(t))}
		}
		return redactURLString(t)
	default:
		return v
	}
}

// unwrapEncodedJSON reads through a body that is a JSON document encoded as
// one JSON string — some APIs answer that way — so its fields are redacted
// and read like any other's.
func unwrapEncodedJSON(v any) any {
	s, ok := v.(string)
	if !ok || !looksLikeJSON([]byte(s)) {
		return v
	}
	var inner any
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	if err := dec.Decode(&inner); err != nil {
		return v
	}
	return inner
}

// accountNumberField reports whether a field is the number of an account
// object: `{"accounts":[{"number":"…"}]}` carries the account number under
// a name that says nothing on its own.
func accountNumberField(parent, name string) bool {
	return strings.Contains(strings.ToLower(parent), "account") && strings.EqualFold(strings.TrimSpace(name), "number")
}

// isFileField reports whether a field holds file content by its name.
func isFileField(key, value string) bool {
	k := strings.ToLower(key)
	if k == "" {
		return false
	}
	for _, f := range fileNameFragments {
		if strings.Contains(k, f) {
			return true
		}
	}
	return k == "content" && len(value) >= contentThreshold
}

// redactURLString blanks the secret query parameters of a URL carried as a
// value — a presigned document link carries its signature in the query.
func redactURLString(s string) string {
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		return s
	}
	if !strings.Contains(s, "?") {
		return s
	}
	u, err := url.Parse(s)
	if err != nil {
		return s
	}
	return redactURL(u)
}

// looksLikeBase64 reports whether s is made of base64 characters only. A
// data URL prefix is allowed.
func looksLikeBase64(s string) bool {
	if i := strings.Index(s, ";base64,"); i >= 0 && i < 64 {
		s = s[i+len(";base64,"):]
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '+', c == '/', c == '=', c == '-', c == '_', c == '\n', c == '\r':
		default:
			return false
		}
	}
	return true
}

// Text bodies — form posts, XML, SOAP, anything that is not JSON — are
// redacted by pattern: every `name=value` or `"name": value` pair and every
// XML element with text content is judged by its name with the same
// sensitiveName test as a JSON field or a header, and content that is a
// file — a base64 document inside an element, a label in a form field — is
// written as its fingerprint, as it is in JSON. Elements go first, so a
// document's padding never reads as a pair.
var (
	textPairPattern   = regexp.MustCompile(`(["']?)([A-Za-z0-9_.\-]+)(["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^&\s,;<>]+)`)
	xmlElementPattern = regexp.MustCompile(`(<((?:[A-Za-z0-9_.\-]*:)?[A-Za-z0-9_.\-]+)(\s[^>]*)?>)([^<]*)(</)`)
)

func redactText(s string) string {
	s = xmlElementPattern.ReplaceAllStringFunc(s, func(m string) string {
		sub := xmlElementPattern.FindStringSubmatch(m)
		if sub == nil {
			return m
		}
		name := sub[2]
		if i := strings.LastIndex(name, ":"); i >= 0 {
			name = name[i+1:]
		}
		switch content := sub[4]; {
		case sensitiveName(name):
			return sub[1] + redacted + sub[5]
		case isFileField(name, content), isFileText(content):
			return sub[1] + fileMarker(content) + sub[5]
		}
		return m
	})
	s = textPairPattern.ReplaceAllStringFunc(s, func(m string) string {
		sub := textPairPattern.FindStringSubmatch(m)
		if sub == nil {
			return m
		}
		switch value := strings.Trim(sub[4], `"'`); {
		case sensitiveName(sub[2]):
			return sub[1] + sub[2] + sub[3] + `"` + redacted + `"`
		case isFileField(sub[2], value), isFileText(value):
			return sub[1] + sub[2] + sub[3] + fileMarker(value)
		}
		return m
	})
	return s
}

// isFileText reports whether a text value is file content by its shape: a
// base64 run from fileThreshold, any text from longStringThreshold.
func isFileText(s string) bool {
	return len(s) >= longStringThreshold || (len(s) >= fileThreshold && looksLikeBase64(s))
}

// fileMarker is the fingerprint of file content written into text, in the
// shape it has in a JSON body.
func fileMarker(content string) string {
	marker, _ := json.Marshal(map[string]any{"$file": fingerprint([]byte(content))})
	return string(marker)
}
