package obs

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestSensitiveNamesAreTheCarriersCredentialFields(t *testing.T) {
	secret := []string{
		"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie",
		"X-Api-Key", "x-api-key", "apiKey", "api_key", "ApiKey",
		"X-Carrier-Credentials", "credentials",
		"Ocp-Apim-Subscription-Key",
		"customerKey", "client_secret", "clientSecret", "accessToken", "refresh_token", "token",
		"password", "Password", "passwd", "signature", "privateKey", "accountKey", "licenseKey",
		"X-Vendor-Api-Key", "apikey", "Some-API-Key", "client_id", "pass", "session", "eid",
		"accountNumber", "account_number", "Idempotency-Key", "idempotencyKey", "ApiId",
	}
	for _, name := range secret {
		if !sensitiveName(name) {
			t.Errorf("%q should be treated as a secret", name)
		}
	}
	plain := []string{
		"Content-Type", "Accept", "X-Request-ID", "deliveryCity", "customerId", "customerReference",
		"bookingId", "trackingNumber", "customerId", "userName", "user", "timestamp",
		"shipmentPricingSessionId", "monkey", "turkey", "",
	}
	for _, name := range plain {
		if sensitiveName(name) {
			t.Errorf("%q should not be treated as a secret", name)
		}
	}
}

func TestHeadersKeepTheirValuesExceptSecrets(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer abc")
	h.Set("Content-Type", "application/json")
	h.Add("Accept", "application/json")
	h.Add("Accept", "text/plain")
	got := redactHeaders(h)
	if got["Authorization"] != redacted {
		t.Errorf("Authorization = %q", got["Authorization"])
	}
	if got["Content-Type"] != "application/json" {
		t.Errorf("Content-Type = %q", got["Content-Type"])
	}
	if got["Accept"] != "application/json, text/plain" {
		t.Errorf("Accept = %q", got["Accept"])
	}
	if redactHeaders(nil) != nil {
		t.Error("no headers should stay nil")
	}
}

func TestURLQuerySecretsAreBlankedAndUserInfoDropped(t *testing.T) {
	u, _ := url.Parse("https://user:pw@api.example.com/v1/track?apiKey=abc&page=2&signature=xyz")
	got := redactURL(u)
	if strings.Contains(got, "abc") || strings.Contains(got, "xyz") || strings.Contains(got, "user:pw") {
		t.Fatalf("secret left in url: %s", got)
	}
	parsed, _ := url.Parse(got)
	q := parsed.Query()
	if q.Get("apiKey") != redacted || q.Get("signature") != redacted || q.Get("page") != "2" {
		t.Errorf("query = %v", q)
	}
}

func TestJSONBodySecretsBlankedFilesFingerprintedValuesKept(t *testing.T) {
	label := strings.Repeat("JVBERi0xLjcNCiWio4", 200) // base64-looking, > fileThreshold
	raw := `{"customerId":"1010093007","customerKey":"s3cret","amount":53.74,"count":4,
		"consignee":{"name":"Maximilian Senkler","password":"x","city":"Gießen"},
		"items":[{"token":"t","description":"Goods"}],
		"shipmentLabel":{"labelPdfBase64Encoded":"` + label + `","labelZpl":["^XA^FDIda Creator^FS^XZ"]},
		"documents":[{"url":"https://storage.googleapis.com/b/o?X-Goog-Signature=abc&X-Goog-Expires=600","content":"` + strings.Repeat("Q", 300) + `"}],
		"accounts":[{"number":"123456789"}],"accountNumber":{"value":"987"},
		"bookingId":"keep-me"}`
	rec := prepareBody("application/json; charset=utf-8", []byte(raw), 0)
	if rec.Truncated || rec.ContentType != "application/json" || rec.Bytes != len(raw) {
		t.Fatalf("record = %+v", rec)
	}
	body := rec.Body.(map[string]any)
	if body["customerKey"] != redacted || body["customerId"] != "1010093007" {
		t.Errorf("top level: %v", body)
	}
	if body["bookingId"] != "keep-me" {
		t.Errorf("bookingId must be kept, got %v", body["bookingId"])
	}
	if body["accountNumber"] != redacted {
		t.Errorf("a carrier account number stays out of the logs, got %v", body["accountNumber"])
	}
	if account := body["accounts"].([]any)[0].(map[string]any); account["number"] != redacted {
		t.Errorf("an account object's number is the account number, got %v", account)
	}
	if _, isFile := body["shipmentLabel"].(map[string]any)["labelZpl"].([]any)[0].(map[string]any)["$file"]; !isFile {
		t.Errorf("a label named as one is a file however short, in a list too: %v", body["shipmentLabel"])
	}
	doc := body["documents"].([]any)[0].(map[string]any)
	if u := doc["url"].(string); strings.Contains(u, "abc") || !strings.Contains(u, "X-Goog-Expires=600") {
		t.Errorf("a presigned url keeps its expiry and loses its signature: %s", u)
	}
	if _, isFile := doc["content"].(map[string]any)["$file"]; !isFile {
		t.Errorf("long document content is a file: %v", doc["content"])
	}
	if body["amount"].(json.Number).String() != "53.74" || body["count"].(json.Number).String() != "4" {
		t.Errorf("numbers must survive unchanged: %v %v", body["amount"], body["count"])
	}
	consignee := body["consignee"].(map[string]any)
	if consignee["password"] != redacted || consignee["city"] != "Gießen" || consignee["name"] != "Maximilian Senkler" {
		t.Errorf("nested: %v", consignee)
	}
	item := body["items"].([]any)[0].(map[string]any)
	if item["token"] != redacted || item["description"] != "Goods" {
		t.Errorf("array element: %v", item)
	}
	file := body["shipmentLabel"].(map[string]any)["labelPdfBase64Encoded"].(map[string]any)["$file"].(fileRecord)
	if file.Bytes != len(label) || len(file.SHA256) != 64 {
		t.Errorf("file record = %+v", file)
	}
	encoded, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "s3cret") || strings.Contains(string(encoded), label[:40]) {
		t.Error("secret or file content survived into the encoded record")
	}
}

func TestBinaryBodiesBecomeAFingerprint(t *testing.T) {
	pdf := []byte("%PDF-1.7 ...binary...")
	rec := prepareBody("application/pdf", pdf, 0)
	file := rec.Body.(map[string]any)["$file"].(fileRecord)
	if file.Bytes != len(pdf) || rec.Bytes != len(pdf) {
		t.Errorf("record = %+v", rec)
	}
}

func TestTextBodiesAreRedactedByPattern(t *testing.T) {
	// A label form's `pass`, an OAuth token form's `client_id`: the
	// exact names and fragments apply to text as they do to JSON.
	form := "user=karl&password=abc123&apiKey=zzz&pass=hunter2&client_id=APIKEY&client_secret=s3&grant_type=client_credentials&city=Tartu"
	got := prepareBody("application/x-www-form-urlencoded", []byte(form), 0).Body.(string)
	for _, secret := range []string{"abc123", "zzz", "hunter2", "APIKEY", "=s3"} {
		if strings.Contains(got, secret) {
			t.Errorf("form secret %q survived: %s", secret, got)
		}
	}
	if !strings.Contains(got, "user=karl") || !strings.Contains(got, "city=Tartu") || !strings.Contains(got, "grant_type=client_credentials") {
		t.Errorf("form values lost: %s", got)
	}

	// A SOAP `session`, a `pass` element, a namespaced token.
	xml := `<Login><Username>karl</Username><Password>abc123</Password><pass>hunter2</pass><session>sess-1</session><soap:Token attr="1">tok</soap:Token><City>Tartu</City></Login>`
	got = prepareBody("text/xml", []byte(xml), 0).Body.(string)
	for _, secret := range []string{"abc123", "hunter2", "sess-1", ">tok<"} {
		if strings.Contains(got, secret) {
			t.Errorf("xml secret %q survived: %s", secret, got)
		}
	}
	if !strings.Contains(got, "<Username>karl</Username>") || !strings.Contains(got, "<City>Tartu</City>") {
		t.Errorf("xml values lost: %s", got)
	}
}

// A document inside an XML element (a proof of delivery, a label) or a form
// field is a file in text as it is in JSON: its size and hash, never its
// bytes.
// Some APIs answer with a JSON document encoded as one JSON string; the
// record reads through to the fields, blanking what it must.
func TestJSONEncodedAsAStringIsReadThrough(t *testing.T) {
	inner := `{"OfferCalcResponse":[{"RequestID":"rq-1","FromPrivatePerson":"1","apikey":"hidden"}]}`
	raw, _ := json.Marshal(inner)
	rec := prepareBody("application/json", raw, 0)
	body, ok := rec.Body.(map[string]any)
	if !ok {
		t.Fatalf("body is not read through: %v", rec.Body)
	}
	item := body["OfferCalcResponse"].([]any)[0].(map[string]any)
	if item["apikey"] != redacted || item["RequestID"] != "rq-1" || item["FromPrivatePerson"] != "1" {
		t.Errorf("fields: %v", item)
	}
}

func TestFilesInTextBodiesAreFingerprinted(t *testing.T) {
	pod := strings.Repeat("JVBERi0xLjcNCiWio4", 100) + "=="
	xml := `<response><pack_no>V1</pack_no><pod>` + pod + `</pod><labelZpl>^XA^FDshort label^FS^XZ</labelZpl></response>`
	got := prepareBody("text/xml", []byte(xml), 0).Body.(string)
	if strings.Contains(got, pod[:40]) || !strings.Contains(got, `<pod>{"$file":{"bytes":`+strconv.Itoa(len(pod))) || !strings.Contains(got, "<pack_no>V1</pack_no>") {
		t.Errorf("xml document: %s", got)
	}
	if strings.Contains(got, "^FDshort label") {
		t.Errorf("a label named as one is a file past a format's length: %s", got)
	}
	form := "pack_no=V1&label=" + pod
	got = prepareBody("application/x-www-form-urlencoded", []byte(form), 0).Body.(string)
	if strings.Contains(got, pod[:40]) || !strings.Contains(got, `label={"$file":`) || !strings.Contains(got, "pack_no=V1") {
		t.Errorf("form document: %s", got)
	}
}

func TestOversizedBodiesAreCutAndMarked(t *testing.T) {
	big := `{"rows":"` + strings.Repeat("x", 500) + `"}`
	rec := prepareBody("application/json", []byte(big), 100)
	if !rec.Truncated || rec.Bytes != len(big) {
		t.Fatalf("record = %+v", rec)
	}
	s, ok := rec.Body.(string)
	if !ok || !strings.HasSuffix(s, "…") || len(s) > 100+len("…") {
		t.Errorf("truncated body = %q", s)
	}
}

func TestEmptyBodyIsEmpty(t *testing.T) {
	rec := prepareBody("", nil, 0)
	if rec.Body != nil || rec.Bytes != 0 || rec.Truncated {
		t.Errorf("record = %+v", rec)
	}
}

func TestArchiveObjectNamesFileByPeerDayAndRequest(t *testing.T) {
	at := mustTime("2026-10-07T09:39:03.895Z")
	got := archiveObjectName("Carrier+Co", "booking.create", "01a115bb-1250-7a0f-9b29-83b9292d8295", at, []byte("one"))
	want := "carrier-co/2026-10-07/01a115bb-1250-7a0f-9b29-83b9292d8295/093903.895-booking.create-"
	if !strings.HasPrefix(got, want) || !strings.HasSuffix(got, ".json") {
		t.Errorf("name = %s, want prefix %s", got, want)
	}
	if other := archiveObjectName("Carrier+Co", "booking.create", "01a115bb-1250-7a0f-9b29-83b9292d8295", at, []byte("two")); other == got {
		t.Error("two records in the same millisecond must get different names")
	}
	if got := archiveObjectName("api", "", "", at, nil); !strings.HasPrefix(got, "api/2026-10-07/no-request-id/093903.895-exchange-") {
		t.Errorf("name without id/operation = %s", got)
	}
}

func TestChangeTrackerReportsRepeatsAndForgetsTheOldest(t *testing.T) {
	tr := newChangeTracker(2)
	if tr.unchanged("a", sha256.Sum256([]byte("1"))) {
		t.Error("first answer is a change")
	}
	if !tr.unchanged("a", sha256.Sum256([]byte("1"))) {
		t.Error("same answer is unchanged")
	}
	if tr.unchanged("a", sha256.Sum256([]byte("2"))) {
		t.Error("different answer is a change")
	}
	tr.unchanged("b", sha256.Sum256([]byte("1")))
	tr.unchanged("c", sha256.Sum256([]byte("1"))) // evicts a
	if tr.unchanged("a", sha256.Sum256([]byte("2"))) {
		t.Error("an evicted key starts over")
	}
}
