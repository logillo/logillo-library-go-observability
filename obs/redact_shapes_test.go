package obs

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The shapes a secret takes beyond a plain JSON field, each judged by the
// one name test: a lowercase compound, a CDATA section, a wrapper element
// with children, a document encoded inside a string, a URL without a
// query, a URL-valued header, a bearer line in text.

func TestKeyNamesAreJudgedInAnyCase(t *testing.T) {
	for _, name := range []string{"accesskey", "ACCESSKEY", "Accesskey", "customerkey", "userkey", "authkey", "licensekey", "x-key", "AccessKey"} {
		if !sensitiveName(name) {
			t.Errorf("%q is a key", name)
		}
	}
	for _, name := range []string{"key", "Key", "monkey", "hockey", "primaryKey", "objectKey", "routingKey", "contractTermKey"} {
		if sensitiveName(name) {
			t.Errorf("%q identifies, it does not authenticate", name)
		}
	}
}

func TestSignatureOptionsAndIdentifiersStayReadable(t *testing.T) {
	for _, name := range []string{"signature", "Signature", "x-signature", "X-Hub-Signature-256", "requestSignature", "signature_v2", "sig", "hmac", "pin", "otp", "accountNo", "account_no", "AccountNr", "acctNumber", "account", "passcode", "sessionId", "SessionID", "Authentication", "X-Auth", "auth"} {
		if !sensitiveName(name) {
			t.Errorf("%q is a secret", name)
		}
	}
	for _, name := range []string{"signatureRequired", "signatureOption", "signatureType", "clientId", "nextPageToken", "pageToken", "continuationToken", "token_type", "shipmentPricingSessionId", "author", "authority"} {
		if sensitiveName(name) {
			t.Errorf("%q is not a secret", name)
		}
	}
}

func TestXMLSecretsInCDATAAndWrappersAreBlankedWhole(t *testing.T) {
	xml := `<Login><Password><![CDATA[s3cret]]></Password><ApiKey><Value>k3y</Value></ApiKey>` +
		`<Credentials><Username>k</Username><Pin>1234</Pin></Credentials><AccountNumber><Value>987654</Value></AccountNumber>` +
		`<City>Tartu</City><Note><![CDATA[call before]]></Note></Login>`
	got := prepareBody("text/xml", []byte(xml), 0).Body.(string)
	for _, secret := range []string{"s3cret", "k3y", "1234", "987654", "<Username>k"} {
		if strings.Contains(got, secret) {
			t.Errorf("%q survived: %s", secret, got)
		}
	}
	if !strings.Contains(got, "<City>Tartu</City>") || !strings.Contains(got, "call before") {
		t.Errorf("values lost: %s", got)
	}
	if !strings.Contains(got, "<Password><redacted></Password>") || !strings.Contains(got, "<Credentials><redacted></Credentials>") {
		t.Errorf("wrapper not blanked whole: %s", got)
	}
}

func TestDocumentsEncodedInsideStringsAreRedacted(t *testing.T) {
	raw := `{"payload":"{\"apiKey\":\"s3cret\",\"id\":\"1\"}","raw":"user=k&password=s3cret2","xml":"<Password>s3cret3</Password><City>Tartu</City>","note":"plain value"}`
	rec := prepareBody("application/json", []byte(raw), 0)
	body := rec.Body.(map[string]any)
	for _, secret := range []string{"s3cret", "s3cret2", "s3cret3"} {
		for _, field := range []string{"payload", "raw", "xml"} {
			if strings.Contains(body[field].(string), secret) {
				t.Errorf("%s carries %q: %s", field, secret, body[field])
			}
		}
	}
	if !strings.Contains(body["payload"].(string), `"id":"1"`) || !strings.Contains(body["raw"].(string), "user=k") || !strings.Contains(body["xml"].(string), "<City>Tartu</City>") || body["note"] != "plain value" {
		t.Errorf("values lost: %v", body)
	}
}

func TestURLsLoseUserInfoAndSignedQueriesWhereverTheyAppear(t *testing.T) {
	raw := `{"callbackUrl":"https://admin:s3cret@example.com/hook","upper":"HTTPS://example.com/x?apiKey=s3cret2","link":"https://x.example/doc?a=1;sig=s3cret3","text":"see https://x.example/d?token=s3cret4 for details"}`
	body := prepareBody("application/json", []byte(raw), 0).Body.(map[string]any)
	for field, secret := range map[string]string{"callbackUrl": "s3cret", "upper": "s3cret2", "link": "s3cret3", "text": "s3cret4"} {
		if strings.Contains(body[field].(string), secret) {
			t.Errorf("%s carries %q: %s", field, secret, body[field])
		}
	}
	if !strings.Contains(body["callbackUrl"].(string), "example.com/hook") || !strings.Contains(body["text"].(string), "for details") {
		t.Errorf("values lost: %v", body)
	}

	h := http.Header{}
	h.Set("Location", "https://storage.googleapis.com/b/o?X-Goog-Signature=s3cret&X-Goog-Expires=600")
	h.Set("Referer", "https://portal/reset?token=s3cret")
	h.Set("Link", `<https://x.example/next?page=2&token=s3cret>; rel="next"`)
	h.Set("Authentication", "s3cret")
	h.Set("X-Auth", "s3cret")
	for name, value := range redactHeaders(h) {
		if strings.Contains(value, "s3cret") {
			t.Errorf("%s carries the secret: %s", name, value)
		}
	}
	if got := redactHeaders(h)["Location"]; !strings.Contains(got, "X-Goog-Expires=600") {
		t.Errorf("Location lost its expiry: %s", got)
	}
}

func TestTextSecretsRunToTheEndOfTheirLine(t *testing.T) {
	text := "Authorization: Bearer s3cret-bearer\npassword=my secret\nauth[password]=x1\nuser=karl\n<Note>Authorization: Bearer s3cret-2</Note>"
	got := prepareBody("text/plain", []byte(text), 0).Body.(string)
	for _, secret := range []string{"s3cret-bearer", "my secret", "=x1", "s3cret-2"} {
		if strings.Contains(got, secret) {
			t.Errorf("%q survived: %s", secret, got)
		}
	}
	if !strings.Contains(got, "user=karl") {
		t.Errorf("value lost: %s", got)
	}
}

func TestIdentifiersInThePlatformsOwnPayloadsStayReadable(t *testing.T) {
	raw := `{"key":"vat-standard","clientId":"party-1","signatureRequired":true,"pdfFormat":"A6","pdfUrl":"https://x.example/label.pdf","nextPageToken":"p2","milestones":[{"key":"ROUTE_LOCATION","type":"X"}],"accounts":[{"number":"123","typeCode":"shipper"}]}`
	body := prepareBody("application/json", []byte(raw), 0).Body.(map[string]any)
	if body["key"] != "vat-standard" || body["clientId"] != "party-1" || body["signatureRequired"] != true || body["pdfFormat"] != "A6" || body["pdfUrl"] != "https://x.example/label.pdf" || body["nextPageToken"] != "p2" {
		t.Errorf("identifiers blanked: %v", body)
	}
	if m := body["milestones"].([]any)[0].(map[string]any); m["key"] != "ROUTE_LOCATION" {
		t.Errorf("a milestone's key is a code: %v", m)
	}
	if a := body["accounts"].([]any)[0].(map[string]any); a["number"] != redacted || a["typeCode"] != "shipper" {
		t.Errorf("account object: %v", a)
	}
}

func TestAPDFIsAFileWhateverTheDeclaredType(t *testing.T) {
	pdf := []byte("%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n" + strings.Repeat("x", 200))
	for _, ct := range []string{"", "text/plain", "application/json"} {
		rec := prepareBody(ct, pdf, 0)
		if _, ok := rec.Body.(map[string]any)["$file"]; !ok {
			t.Errorf("content type %q: pdf bytes recorded as text: %v", ct, rec.Body)
		}
	}
	png := append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 64)...)
	if _, ok := prepareBody("text/plain", png, 0).Body.(map[string]any)["$file"]; !ok {
		t.Error("png bytes recorded as text")
	}
}

func TestNDJSONAndBOMBodiesStillRedact(t *testing.T) {
	ndjson := "{\"a\":1}\n{\"password\":\"s3cret\"}\n"
	got := prepareBody("application/x-ndjson", []byte(ndjson), 0)
	if s, ok := got.Body.(string); !ok || strings.Contains(s, "s3cret") || !strings.Contains(s, `{"a":1}`) {
		t.Errorf("ndjson: %v", got.Body)
	}
	bom := "\xEF\xBB\xBF{\"token\":\"s3cret\",\"id\":\"1\"}"
	body, ok := prepareBody("application/json", []byte(bom), 0).Body.(map[string]any)
	if !ok || body["token"] != redacted || body["id"] != "1" {
		t.Errorf("bom: %v", body)
	}
}

func TestErrorTextBlanksTheURLsSecrets(t *testing.T) {
	err := &url.Error{Op: "Post", URL: "https://ledger.example/api?ApiId=1&timestamp=2&signature=s3cret", Err: errors.New("dial tcp: connection refused")}
	got := ErrorText(err)
	if strings.Contains(got, "s3cret") || !strings.Contains(got, "connection refused") || !strings.Contains(got, "ledger.example") {
		t.Errorf("error text = %q", got)
	}
	wrapped := errors.New("call failed: Get https://x.example/a?token=s3cret: timeout")
	if got := ErrorText(wrapped); strings.Contains(got, "s3cret") || !strings.Contains(got, "timeout") {
		t.Errorf("wrapped error text = %q", got)
	}
}

func TestAPeersOwnRuleBlanksWhatNoGenericRuleCan(t *testing.T) {
	r := &rules{sensitive: func(parent, name string) bool { return parent == "parties" && name == "id" }}
	raw := []byte(`{"parties":[{"id":"20255504.EE0001","name":"Acme","type":"Consignor"}],"shipment":{"id":"S-1"}}`)
	body := r.prepareBody("application/json", raw, len(raw), 0).Body.(map[string]any)
	party := body["parties"].([]any)[0].(map[string]any)
	if party["id"] != redacted || party["name"] != "Acme" {
		t.Errorf("party: %v", party)
	}
	if body["shipment"].(map[string]any)["id"] != "S-1" {
		t.Errorf("another id must stay: %v", body["shipment"])
	}
}

func TestLogLineBodiesAreCutWhileTheRecordKeepsThemWhole(t *testing.T) {
	raw := []byte(`{"items":"` + strings.Repeat("x", 300) + `","password":"s3cret"}`)
	full := defaultRules.prepareBody("application/json", raw, len(raw), 0)
	if full.Truncated || full.Body.(map[string]any)["password"] != redacted {
		t.Fatalf("whole record = %+v", full)
	}
	cut := full.cut(100)
	if !cut.Truncated || len(cut.Body.(string)) > 110 || strings.Contains(cut.Body.(string), "s3cret") {
		t.Errorf("cut record = %+v", cut)
	}
}
