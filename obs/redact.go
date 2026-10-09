package obs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// What a captured exchange may never contain, and what it carries in place
// of what it drops:
//
//   - A secret — a key, a password, a token, a signature — is written as
//     "<redacted>", wherever it sits: a header, a query parameter, a JSON
//     field, a form field, an XML element or a `name=value` pair in text,
//     a document encoded inside a string. Field names decide, matched
//     case-insensitively against the rules below; a value is never
//     inspected to guess whether it is a secret.
//   - A file — a label, a PDF, an image, anything base64 — is written as
//     its size and SHA-256, so a dispute can still prove which bytes were
//     exchanged without the bytes filling the log.
//   - A body past the size limit is cut at the limit and marked.
//
// Over-redaction hides a field from a debugging log; under-redaction leaks
// a partner's key. The rules lean towards the first, except where a name is
// an identifier in the platform's own payloads: a bare `key`, a `clientId`,
// a `signatureRequired` option stay readable.

const (
	redacted = "<redacted>"

	// defaultBodyLimit caps one captured body on a log line. Cloud Logging
	// accepts 256 KiB per entry; a request and a response at this limit,
	// JSON-escaped, plus headers fit.
	defaultBodyLimit = 64 << 10

	// captureLimit caps what is held and read of one body for the record
	// the archive keeps; a body past it is kept as its size and
	// fingerprint.
	captureLimit = 2 << 20

	// fileThreshold is the length from which a base64 string is treated as
	// file content rather than a value worth reading.
	fileThreshold = 1024

	// longStringThreshold is the length from which any string is treated as
	// content — a ZPL label, a document — and fingerprinted.
	longStringThreshold = 32 << 10

	// contentThreshold is the length from which a field named `content` is
	// file content rather than a note.
	contentThreshold = 256

	// shortValueLimit is the length up to which a value under a file-named
	// field is a format or a flag — `pdfFormat: "A6"` — not a file.
	shortValueLimit = 16
)

// sensitiveFragments mark a header, parameter or field as a secret when its
// name contains one of them: the names credentials travel under at the
// platform's boundaries — Authorization and X-Carrier-Credentials on the
// platform side; at the peers an API key header, a customer key, an OAuth
// client id, secret and access token, a login password, a passcode, an
// HMAC. A partner account number is not a credential but is billed against,
// so it stays out of the logs too — under its own names, and as the
// `number` of an account object (`accounts[].number`).
// An idempotency key is sensitive by the integration idempotency standard.
var sensitiveFragments = []string{
	"password", "passwd", "passcode", "passphrase", "secret", "token", "credential",
	"apikey", "api_key", "api-key", "authorization", "hmac",
	"subscription-key", "subscription_key", "subscriptionkey", "cookie",
	"accountnumber", "account_number", "account-number", "accountno", "account_no", "account-no", "accountnr", "acctnumber",
	"client_id", "idempotency",
}

// sensitiveExact are whole names that are secrets but match no fragment: a
// login's `pass` or `pwd`, a SOAP `session` ticket, an `eid` login object
// (an electronic-identity user name and password), a one-time code, an
// account under its bare name, an API id that is provisioned as a secret.
var sensitiveExact = map[string]bool{
	"pass": true, "pwd": true, "pin": true, "otp": true, "jwt": true, "ticket": true,
	"session": true, "sessionid": true, "session_id": true, "session-id": true,
	"eid": true, "sig": true, "auth": true, "authentication": true,
	"account": true, "apiid": true, "api_id": true, "api-id": true,
}

// fragmentAllowed are names that contain a sensitive fragment but identify
// or describe rather than authenticate: a pagination token, a token's type.
var fragmentAllowed = map[string]bool{
	"nextpagetoken": true, "pagetoken": true, "page_token": true, "continuationtoken": true,
	"tokentype": true, "token_type": true,
}

// keyNameAllowed are names ending in "key" that identify, not authenticate,
// and English words that end in the letters.
var keyNameAllowed = map[string]bool{
	"primarykey": true, "sortkey": true, "partitionkey": true, "cachekey": true,
	"routingkey": true, "changekey": true, "mapkey": true, "foreignkey": true,
	"publickey": true, "objectkey": true, "rowkey": true, "contracttermkey": true,
	"monkey": true, "turkey": true, "donkey": true, "hockey": true, "jockey": true, "whiskey": true, "lackey": true,
}

// fileNameFragments mark a field as file content by name — a label, a
// document, an image — whatever its length, so a short ZPL label is treated
// like a long PDF.
var fileNameFragments = []string{"base64", "zpl", "pdf", "encodedlabel", "labelimage", "labeldata", "imagedata", "file_pdf"}

// urlValuedHeaders carry a URL whose query may be signed.
var urlValuedHeaders = map[string]bool{"location": true, "content-location": true, "referer": true, "link": true, "refresh": true}

// rules are the redaction rules one capturer applies: the library's own,
// plus what a service adds for a peer whose secrets travel under names no
// generic rule can know.
type rules struct {
	// sensitive reports whether a field is a secret for this peer, judged
	// by its name and its parent's. Nil adds nothing.
	sensitive func(parent, name string) bool
}

// defaultRules applies the library's rules alone.
var defaultRules = &rules{}

// sensitiveName reports whether a header, parameter or field name denotes
// a secret.
func sensitiveName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	if sensitiveExact[n] || authName(n) {
		return true
	}
	if fragmentAllowed[n] {
		return false
	}
	for _, f := range sensitiveFragments {
		if strings.Contains(n, f) {
			return true
		}
	}
	if signatureName(n) {
		return true
	}
	// A name whose last word is "key" is a credential unless it is a known
	// identifier — customerKey, client_key, X-Account-Key all authenticate.
	if endsInKeyWord(n) && !keyNameAllowed[n] {
		return true
	}
	return false
}

// authName matches a header or field named `auth` or ending in the word:
// `X-Auth`, `basic_auth`.
func authName(n string) bool {
	return n == "auth" || strings.HasSuffix(n, "-auth") || strings.HasSuffix(n, "_auth") || strings.HasSuffix(n, ".auth")
}

// signatureName matches a request signature — `signature`, `x-signature`,
// `X-Hub-Signature-256`, `requestSignature` — and not a shipment option
// that starts with the word: `signatureRequired`, `signatureOption`.
func signatureName(n string) bool {
	i := strings.Index(n, "signature")
	if i < 0 {
		return false
	}
	rest := n[i+len("signature"):]
	return rest == "" || (rest[0] < 'a' || rest[0] > 'z')
}

// endsInKeyWord reports whether a lowercased name ends in the word "key".
// A bare `key` is an identifier in the platform's own payloads and stays.
func endsInKeyWord(n string) bool {
	return n != "key" && strings.HasSuffix(n, "key")
}

// field reports whether a field is a secret under these rules.
func (r *rules) field(parent, name string) bool {
	if sensitiveName(name) || accountNumberField(parent, name) {
		return true
	}
	return r.sensitive != nil && r.sensitive(parent, name)
}

// redactHeaders returns the headers with secret values blanked, each header
// as one string (multiple values joined). A URL-valued header keeps its
// URL with the query's secrets blanked.
func (r *rules) redactHeaders(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for name, values := range h {
		switch {
		case r.field("", name):
			out[name] = redacted
		case urlValuedHeaders[strings.ToLower(name)]:
			out[name] = redactQueriesIn(redactURLsIn(strings.Join(values, ", ")))
		default:
			out[name] = strings.Join(values, ", ")
		}
	}
	return out
}

// redactURL returns the URL with secret query parameters blanked. User
// info in the URL is dropped outright. A query that does not parse whole
// is written from the pairs that did.
func redactURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	c := *u
	c.User = nil
	if c.RawQuery != "" {
		c.RawQuery = redactQuery(c.RawQuery)
	}
	return c.String()
}

// redactQuery returns a query string with secret parameters blanked.
func redactQuery(raw string) string {
	q, err := url.ParseQuery(raw)
	changed := err != nil
	for name := range q {
		if sensitiveName(name) {
			q[name] = []string{redacted}
			changed = true
		}
	}
	if !changed {
		return raw
	}
	return q.Encode()
}

var (
	urlPattern   = regexp.MustCompile(`(?i)https?://[^\s<>"'\\]+`)
	queryPattern = regexp.MustCompile(`\?[^\s<>"'\\]+`)
)

// redactURLsIn blanks the secrets of every URL carried in a text: a signed
// query, user information.
func redactURLsIn(s string) string {
	return urlPattern.ReplaceAllStringFunc(s, redactURLString)
}

// redactQueriesIn blanks the secrets of every query string in a text, a
// relative URL's included: `/download?token=…`.
func redactQueriesIn(s string) string {
	return queryPattern.ReplaceAllStringFunc(s, func(m string) string {
		return "?" + redactQuery(m[1:])
	})
}

// redactURLString blanks the secret query parameters and the user
// information of a URL carried as a value — a presigned document link
// carries its signature in the query.
func redactURLString(s string) string {
	if !isURL(s) {
		return s
	}
	u, err := url.Parse(s)
	if err != nil {
		return s
	}
	if u.User == nil && u.RawQuery == "" {
		return s
	}
	return redactURL(u)
}

// ErrorText returns an error's text with the secrets of any URL in it
// blanked: a transport error names the URL it failed on, query and all.
func ErrorText(err error) string {
	if err == nil {
		return ""
	}
	var ue *url.Error
	if errors.As(err, &ue) && ue.URL != "" && ue.Err != nil {
		return redactURLsIn(ue.Op + " " + ue.URL + ": " + ue.Err.Error())
	}
	return redactURLsIn(err.Error())
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

func fileValue(b []byte) map[string]any {
	return map[string]any{"$file": fingerprint(b)}
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

// cut returns the record with its body cut at limit bytes for a log line.
// A parsed body is written as JSON text when cut; a short body is kept as
// it is.
func (b bodyRecord) cut(limit int) bodyRecord {
	if limit <= 0 {
		limit = defaultBodyLimit
	}
	switch body := b.Body.(type) {
	case nil:
		return b
	case string:
		if len(body) > limit {
			b.Body = body[:runeBoundary(body, limit)] + "…"
			b.Truncated = true
		}
		return b
	default:
		encoded, err := json.Marshal(body)
		if err == nil && len(encoded) > limit {
			b.Body = string(encoded[:runeBoundary(string(encoded), limit)]) + "…"
			b.Truncated = true
		}
		return b
	}
}

// runeBoundary returns the largest index at or before limit that starts a
// rune, so a cut never splits one.
func runeBoundary(s string, limit int) int {
	for limit > 0 && limit < len(s) && !utf8.RuneStart(s[limit]) {
		limit--
	}
	return limit
}

// prepareBody turns raw body bytes into what is recorded: redacted, files
// fingerprinted. total is the size of the body as exchanged when raw is
// only its prefix; a body held past limit is kept as its fingerprint.
func (r *rules) prepareBody(contentType string, raw []byte, total int, limit int) bodyRecord {
	if limit <= 0 {
		limit = captureLimit
	}
	mediaType := contentType
	if mt, _, err := mime.ParseMediaType(contentType); err == nil {
		mediaType = mt
	}
	if total < len(raw) {
		total = len(raw)
	}
	rec := bodyRecord{Bytes: total, ContentType: mediaType, Truncated: total > len(raw)}
	if len(raw) == 0 {
		return rec
	}

	if isBinaryMediaType(mediaType) || isBinaryContent(raw) || len(raw) > limit {
		rec.Body = fileValue(raw)
		return rec
	}

	raw = bytes.TrimPrefix(raw, []byte("\xEF\xBB\xBF"))
	if v, ok := r.parseJSON(raw); ok {
		rec.Body = v
		return rec
	}

	rec.Body = r.redactText(string(raw))
	return rec
}

// parseJSON decodes one JSON document and redacts it. A body that is a
// JSON document encoded as one JSON string is read through to its fields.
// A body with content after the first document — one record of NDJSON is
// not the body — is left to the text rules.
func (r *rules) parseJSON(raw []byte) (any, bool) {
	if !looksLikeJSON(raw) {
		return nil, false
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	if int(dec.InputOffset()) < len(bytes.TrimRight(raw, " \t\r\n")) {
		return nil, false
	}
	v = unwrapEncodedJSON(v)
	return r.redactValue(v, ""), true
}

// looksLikeJSON reports whether a body is a JSON object or array, directly
// or encoded as one JSON string (`"{\"…`).
func looksLikeJSON(raw []byte) bool {
	trimmed := bytes.TrimLeft(bytes.TrimPrefix(raw, []byte("\xEF\xBB\xBF")), " \t\r\n")
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
	case "application/pdf", "application/octet-stream", "application/zip", "application/gzip", "application/x-gzip",
		"application/x-zpl", "application/vnd.ms-excel",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
		return true
	}
	return false
}

// isBinaryContent reports whether a body is a file by its first bytes,
// whatever the declared media type: a PDF handed over as text/plain is
// still a PDF. Bytes that are not text — a NUL, a byte outside UTF-8 — are
// a file; a sniffed type alone is not, since a short text can start like
// an image's signature.
func isBinaryContent(raw []byte) bool {
	if bytes.HasPrefix(raw, []byte("%PDF")) {
		return true
	}
	head := raw
	if len(head) > 512 {
		head = head[:512]
	}
	if bytes.IndexByte(head, 0) >= 0 || !utf8.Valid(head) {
		return true
	}
	return false
}

// redactValue walks parsed JSON: secret fields are blanked by name, file
// content is replaced by its fingerprint, a document encoded inside a
// string is redacted in place. key is the field the value sits under — ""
// at the root; an array's elements sit under the array's own field, so a
// list of labels is a list of files.
func (r *rules) redactValue(v any, key string) any {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if r.field(key, k) {
				t[k] = redacted
				continue
			}
			t[k] = r.redactValue(child, k)
		}
		return t
	case []any:
		for i, child := range t {
			t[i] = r.redactValue(child, key)
		}
		return t
	case string:
		return r.redactString(key, t)
	default:
		return v
	}
}

// redactString handles one string value: a file by name or shape, a JSON
// document, a form or XML document, a URL, or a plain value.
func (r *rules) redactString(key, s string) any {
	if isFileField(key, s) || isFileText(s) {
		return fileValue([]byte(s))
	}
	if looksLikeJSON([]byte(s)) {
		if v, ok := r.parseJSON([]byte(s)); ok {
			if encoded, err := json.Marshal(v); err == nil {
				return string(encoded)
			}
		}
	}
	if looksLikeDocument(s) {
		return r.redactText(s)
	}
	return redactURLsIn(s)
}

// looksLikeDocument reports whether a string value is a form or an XML
// document rather than a value: `user=k&password=x`, `<Login>…`.
func looksLikeDocument(s string) bool {
	trimmed := strings.TrimLeft(s, " \t\r\n")
	if strings.HasPrefix(trimmed, "<") {
		return true
	}
	if isURL(s) || !strings.Contains(s, "=") || strings.ContainsAny(s, " \n") || looksLikeBase64(s) {
		return false
	}
	q, err := url.ParseQuery(s)
	return err == nil && len(q) > 0
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

// isFileField reports whether a field holds file content by its name. A
// short value or a URL under a file-named field is a format or a link, not
// the file.
func isFileField(key, value string) bool {
	k := strings.ToLower(key)
	if k == "" {
		return false
	}
	if k == "content" {
		return len(value) >= contentThreshold
	}
	if len(value) <= shortValueLimit || isURL(value) {
		return false
	}
	for _, f := range fileNameFragments {
		if strings.Contains(k, f) {
			return true
		}
	}
	return false
}

func isURL(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
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

// isFileText reports whether a text value is file content by its shape: a
// base64 run from fileThreshold, any text from longStringThreshold.
func isFileText(s string) bool {
	return len(s) >= longStringThreshold || (len(s) >= fileThreshold && looksLikeBase64(s))
}

// fileMarker is the fingerprint of file content written into text, in the
// shape it has in a JSON body.
func fileMarker(content string) string {
	marker, _ := json.Marshal(fileValue([]byte(content)))
	return string(marker)
}

// Text bodies — form posts, XML, SOAP, anything that is not JSON — are
// redacted by pattern. An XML element whose name is a secret is blanked
// whole, attributes, children and CDATA included; a leaf element holding a
// document is written as the document's fingerprint. Then every
// `name=value` or `"name": value` pair is judged by its name with the same
// test as a JSON field or a header; a secret's value runs to the end of its
// line or segment, so `Authorization: Bearer <token>` loses the token, not
// the word before it.
var (
	xmlTagPattern   = regexp.MustCompile(`<(/?)((?:[A-Za-z0-9_.\-]*:)?([A-Za-z0-9_.\-]+))((?:\s[^>]*?)?)(/?)>`)
	cdataPattern    = regexp.MustCompile(`(?s)^\s*<!\[CDATA\[(.*)\]\]>\s*$`)
	textPairPattern = regexp.MustCompile(`(["']?)([A-Za-z0-9_.\-\[\]]+)(["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^&\s,;<>]+)`)
)

func (r *rules) redactText(s string) string {
	return r.redactTextPairs(r.redactXML(redactURLsIn(s)))
}

// xmlTag is one tag of an XML text, as the tokenizer found it.
type xmlTag struct {
	start, end  int
	name        string // the local name
	closing     bool   // </name>
	selfClosing bool   // <name/>
	attrs       bool   // the tag carries attributes
}

// redactXML tokenizes the tags of an XML text once and walks them. A
// secret element's whole content, to its matching close tag, is blanked
// along with its attributes; a secret element with no close tag is blanked
// to the end; a leaf whose content is a file is fingerprinted; any other
// element is left as it is. One pass over the tags, so a page of unclosed
// tags costs the same as a document.
func (r *rules) redactXML(s string) string {
	if !strings.Contains(s, "<") {
		return s
	}
	tags := tokenizeXML(s)
	if len(tags) == 0 {
		return s
	}
	var out strings.Builder
	cursor := 0
	for i := 0; i < len(tags); i++ {
		tag := tags[i]
		out.WriteString(s[cursor:tag.start])
		if tag.closing {
			out.WriteString(s[tag.start:tag.end])
			cursor = tag.end
			continue
		}
		if !r.field("", tag.name) {
			if j := i + 1; !tag.selfClosing && j < len(tags) && tags[j].closing && tags[j].name == tag.name {
				content := stripCDATA(s[tag.end:tags[j].start])
				if isFileField(tag.name, content) || isFileText(content) {
					out.WriteString(s[tag.start:tag.end])
					out.WriteString(fileMarker(content))
					out.WriteString(s[tags[j].start:tags[j].end])
					cursor = tags[j].end
					i = j
					continue
				}
			}
			out.WriteString(s[tag.start:tag.end])
			cursor = tag.end
			continue
		}
		// A secret element: its attributes go, and its content to the
		// matching close tag.
		out.WriteString("<" + qualifiedName(s, tag))
		if tag.attrs {
			out.WriteString(" " + redacted)
		}
		if tag.selfClosing {
			out.WriteString("/>")
			cursor = tag.end
			continue
		}
		out.WriteString(">" + redacted)
		depth := 1
		j := i + 1
		for ; j < len(tags); j++ {
			if tags[j].name != tag.name || tags[j].selfClosing {
				continue
			}
			if tags[j].closing {
				depth--
				if depth == 0 {
					break
				}
			} else {
				depth++
			}
		}
		if j == len(tags) {
			return out.String()
		}
		out.WriteString(s[tags[j].start:tags[j].end])
		cursor = tags[j].end
		i = j
	}
	out.WriteString(s[cursor:])
	return out.String()
}

// tokenizeXML finds every tag of an XML text, in order.
func tokenizeXML(s string) []xmlTag {
	matches := xmlTagPattern.FindAllStringSubmatchIndex(s, -1)
	tags := make([]xmlTag, 0, len(matches))
	for _, m := range matches {
		tags = append(tags, xmlTag{
			start:       m[0],
			end:         m[1],
			name:        s[m[6]:m[7]],
			closing:     m[3] > m[2],
			selfClosing: m[11] > m[10],
			attrs:       m[9] > m[8],
		})
	}
	return tags
}

// qualifiedName returns the tag's name with its namespace prefix.
func qualifiedName(s string, tag xmlTag) string {
	m := xmlTagPattern.FindStringSubmatchIndex(s[tag.start:tag.end])
	if m == nil {
		return tag.name
	}
	return s[tag.start+m[4] : tag.start+m[5]]
}

// stripCDATA returns the content of a CDATA section, or s itself.
func stripCDATA(s string) string {
	if m := cdataPattern.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return s
}

// redactTextPairs blanks the value of every `name=value` or `name: value`
// pair whose name is a secret, to the end of its line or segment, and
// fingerprints a value that is a file.
func (r *rules) redactTextPairs(s string) string {
	var out strings.Builder
	cursor := 0
	for cursor < len(s) {
		loc := textPairPattern.FindStringSubmatchIndex(s[cursor:])
		if loc == nil {
			break
		}
		start, end := cursor+loc[0], cursor+loc[1]
		name := s[cursor+loc[4] : cursor+loc[5]]
		valueStart := cursor + loc[8]
		value := strings.Trim(s[valueStart:end], `"'`)
		out.WriteString(s[cursor:start])
		switch {
		case strings.HasPrefix(s[valueStart:], "//"):
			// A URL's scheme is not a name: its query was judged as a
			// URL, and its pairs are judged next.
			out.WriteString(s[start:valueStart])
			end = valueStart
		case strings.HasPrefix(value, redacted), strings.HasPrefix(value, "%3Credacted%3E"):
			// Blanked already, by the URL rules.
			out.WriteString(s[start:end])
		case r.field("", name):
			out.WriteString(s[start:valueStart])
			end = valueStart + segmentEnd(s[valueStart:])
			out.WriteString(`"` + redacted + `"`)
		case isFileField(name, value), isFileText(value):
			out.WriteString(s[start:valueStart])
			out.WriteString(fileMarker(value))
		default:
			out.WriteString(s[start:end])
		}
		cursor = end
	}
	out.WriteString(s[cursor:])
	return out.String()
}

// segmentEnd returns the length of a secret's value in text: a quoted
// value whole (an escaped quote inside it stepped over), otherwise up to
// the end of the line or the next `&`, `;`, `,` or tag.
func segmentEnd(s string) int {
	if len(s) > 0 && (s[0] == '"' || s[0] == '\'') {
		for i := 1; i < len(s); i++ {
			switch s[i] {
			case '\\':
				i++
			case s[0]:
				return i + 1
			}
		}
	}
	if i := strings.IndexAny(s, "&;,<>\r\n"); i >= 0 {
		return i
	}
	return len(s)
}
