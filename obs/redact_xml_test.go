package obs

import (
	"strings"
	"testing"
	"time"
)

// The XML scanner against the shapes a carrier's answer takes: self-closing
// secrets with the value in an attribute, a secret with no close tag, a
// namespaced close tag, nested elements of one name, and a page of unclosed
// tags, which must cost no more than a document.

func TestXMLSecretsInAttributesAndUnclosedElementsAreBlanked(t *testing.T) {
	xml := `<Login><Password value="s3cret-attr"/><ApiKey value="s3cret-attr2" /><User>k</User><Token>s3cret-unclosed`
	got := prepareBody("text/xml", []byte(xml), 0).Body.(string)
	for _, secret := range []string{"s3cret-attr", "s3cret-attr2", "s3cret-unclosed"} {
		if strings.Contains(got, secret) {
			t.Errorf("%q survived: %s", secret, got)
		}
	}
	if !strings.Contains(got, "<User>k</User>") {
		t.Errorf("value lost: %s", got)
	}
}

func TestXMLScannerKeepsStructureAroundSecrets(t *testing.T) {
	xml := `<soap:Envelope><soap:Body><ns:Credentials attr="1"><ns:User>k</ns:User><ns:Pin>1234</ns:Pin></ns:Credentials>` +
		`<Item><Item><Name>inner</Name></Item><Password>s3cret</Password></Item><City>Tartu</City></soap:Body></soap:Envelope>`
	got := prepareBody("text/xml", []byte(xml), 0).Body.(string)
	for _, secret := range []string{"1234", "s3cret", `attr="1"`} {
		if strings.Contains(got, secret) {
			t.Errorf("%q survived: %s", secret, got)
		}
	}
	for _, kept := range []string{"<ns:Credentials <redacted>><redacted></ns:Credentials>", "<Name>inner</Name>", "<City>Tartu</City>", "</soap:Envelope>"} {
		if !strings.Contains(got, kept) {
			t.Errorf("%q lost: %s", kept, got)
		}
	}
}

func TestAPageOfUnclosedTagsIsRedactedInLinearTime(t *testing.T) {
	line := "line of text<br>\n<img src=\"x\"><tr><td>cell"
	timed := func(repeats int) (time.Duration, bodyRecord) {
		page := []byte(strings.Repeat(line, repeats))
		start := time.Now()
		rec := prepareBody("text/html", page, 0)
		return time.Since(start), rec
	}
	small, _ := timed(captureLimit / 200)
	large, rec := timed(captureLimit / 50)
	// Four times the page costs about four times the work; a quadratic
	// scanner would cost sixteen.
	if large > 8*small+50*time.Millisecond {
		t.Fatalf("small page %s, four times the page %s", small, large)
	}
	if _, isText := rec.Body.(string); !isText {
		t.Errorf("a page is text: %T", rec.Body)
	}
}

func TestTextThatStartsLikeAnImageIsStillText(t *testing.T) {
	for _, text := range []string{"BM-REF-1 ok, delivered", "GIF89a is a format name", "OTTO MAIER GMBH, Berlin", "ID3 tag list follows"} {
		if _, isFile := prepareBody("text/plain", []byte(text), 0).Body.(map[string]any); isFile {
			t.Errorf("%q recorded as a file", text)
		}
	}
	utf16 := []byte("<\x00L\x00o\x00g\x00i\x00n\x00>\x00s\x003\x00c\x00r\x00e\x00t\x00")
	if _, isFile := prepareBody("text/xml; charset=utf-16", utf16, 0).Body.(map[string]any); !isFile {
		t.Error("utf-16 text the scanners cannot judge is a file")
	}
}

func TestRelativeURLsInHeadersAndTargetsLoseTheirQuerySecrets(t *testing.T) {
	got := redactQueriesIn("/download?token=s3cret&id=1")
	if strings.Contains(got, "s3cret") || !strings.Contains(got, "id=1") {
		t.Errorf("relative query = %s", got)
	}
	link := `</next?page=2&token=s3cret>; rel="next"`
	if got := redactQueriesIn(link); strings.Contains(got, "s3cret") || !strings.Contains(got, "page=2") {
		t.Errorf("link header = %s", got)
	}
}

func TestTextPairsStopAtCommasAndStepOverEscapedQuotes(t *testing.T) {
	got := prepareBody("text/plain", []byte(`pin: 1234, id: 5, city: Tartu`), 0).Body.(string)
	if strings.Contains(got, "1234") || !strings.Contains(got, "id: 5, city: Tartu") {
		t.Errorf("comma segments = %s", got)
	}
	got = prepareBody("text/plain", []byte(`password="a\"b-s3cret" next=1`), 0).Body.(string)
	if strings.Contains(got, "s3cret") || !strings.Contains(got, "next=1") {
		t.Errorf("escaped quote = %s", got)
	}
	got = prepareBody("text/plain", []byte(`see http://x/a?token=s3cret: timeout`), 0).Body.(string)
	if strings.Contains(got, "s3cret") || !strings.Contains(got, "timeout") {
		t.Errorf("url then text = %s", got)
	}
}

func TestBase64PaddingIsNotAForm(t *testing.T) {
	body := prepareBody("application/json", []byte(`{"blob":"abc+def/ghipassword=="}`), 0).Body.(map[string]any)
	if body["blob"] != "abc+def/ghipassword==" {
		t.Errorf("blob = %v", body["blob"])
	}
}

func TestTwoPeerRulesBothApply(t *testing.T) {
	c := NewCapturer("x",
		SensitiveFields(func(parent, name string) bool { return name == "a" }),
		SensitiveFields(func(parent, name string) bool { return name == "b" }))
	if !c.rules.field("", "a") || !c.rules.field("", "b") || c.rules.field("", "c") {
		t.Error("both rules must apply")
	}
}

func TestACutNeverSplitsARune(t *testing.T) {
	rec := bodyRecord{Body: "Gießen ist eine Stadt"}.cut(4)
	if s := rec.Body.(string); strings.ContainsRune(s, '�') || !strings.HasPrefix(s, "Gie") {
		t.Errorf("cut = %q", s)
	}
}
