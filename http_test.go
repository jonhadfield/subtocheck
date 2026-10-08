package subtocheck

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newResponse(status int, body string, header http.Header) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

// sampleFor builds a response, CNAME chain and redirect list that satisfy the pattern.
func sampleFor(p vPattern) (*http.Response, []string, []string) {
	status := 200
	if len(p.responseCodes) > 0 {
		status = p.responseCodes[0]
	}
	header := http.Header{}
	for i, s := range p.headerStrings {
		name, value, found := strings.Cut(s, ": ")
		if !found {
			name, value = "X-Sample-"+string(rune('a'+i)), s
		}
		header.Add(name, value)
	}
	var cnames, redirects []string
	if len(p.cnames) > 0 {
		cnames = []string{"tenant." + p.cnames[0]}
	}
	if len(p.redirectStrings) > 0 {
		redirects = []string{"https://" + p.redirectStrings[0]}
	}
	body := "<html>" + strings.Join(p.bodyStrings, " ") + "</html>"
	return newResponse(status, body, header), cnames, redirects
}

func TestEveryPatternMatchesItsOwnFingerprint(t *testing.T) {
	for _, p := range vPatterns {
		resp, cnames, redirects := sampleFor(p)
		got := checkVulnerable("https://example.com", resp, cnames, redirects)
		if got.platform != p.platform {
			t.Errorf("%s: fingerprint matched %q instead", p.platform, got.platform)
		}
	}
}

func TestEveryPatternRequiresMoreThanStatus(t *testing.T) {
	for _, p := range vPatterns {
		if len(p.bodyStrings) == 0 && len(p.redirectStrings) == 0 && len(p.headerStrings) == 0 {
			t.Errorf("%s: pattern has nothing to match beyond DNS and status", p.platform)
		}
		if len(p.bodyStrings) > 0 && p.bodyStringMatch != "all" && p.bodyStringMatch != "any" {
			t.Errorf("%s: bodyStringMatch must be all or any, got %q", p.platform, p.bodyStringMatch)
		}
	}
}

func TestGeneric404IsNotVulnerable(t *testing.T) {
	resp := newResponse(404, "<html><h1>404 Not Found</h1><p>page not found</p></html>", nil)
	if got := checkVulnerable("https://example.com", resp, nil, nil); got.kind != "" {
		t.Errorf("generic 404 matched %s", got.platform)
	}
}

// The body used to be read once per pattern, so every pattern after the first saw an
// empty body and a dangling S3 bucket was never reported.
func TestLaterPatternsSeeTheBody(t *testing.T) {
	body := "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message><BucketName>assets.example.com</BucketName></Error>"
	resp := newResponse(404, body, nil)
	if got := checkVulnerable("https://assets.example.com", resp, nil, nil); got.platform != "S3" {
		t.Errorf("expected S3, got %q", got.platform)
	}
}

func TestS3ExcludesGoogleCloudStorage(t *testing.T) {
	body := "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist.</Message><BucketName>x</BucketName></Error>"
	header := http.Header{"X-Guploader-Uploadid": []string{"abc"}}
	if got := checkVulnerable("https://example.com", newResponse(404, body, header), nil, nil); got.kind != "" {
		t.Errorf("Google Cloud Storage error matched %s", got.platform)
	}
}

func TestCNAMERequiredForGenericFingerprint(t *testing.T) {
	body := "project not found"
	if got := checkVulnerable("https://example.com", newResponse(404, body, nil), nil, nil); got.kind != "" {
		t.Errorf("matched %s without a surge.sh CNAME", got.platform)
	}
	got := checkVulnerable("https://example.com", newResponse(404, body, nil), []string{"na-west1.surge.sh"}, nil)
	if got.platform != "Surge.sh" {
		t.Errorf("expected Surge.sh, got %q", got.platform)
	}
}

func TestNotBodyStringsExclude(t *testing.T) {
	body := "Do you want to register <em>x.wordpress.com</em> doesn&#8217;t&nbsp;exist but it cannot be registered"
	if got := checkVulnerable("https://example.com", newResponse(200, body, nil), nil, nil); got.kind != "" {
		t.Errorf("matched %s despite exclusion", got.platform)
	}
}

func TestEdgeCaseIsLabelled(t *testing.T) {
	body := "There isn't a GitHub Pages site here."
	got := checkVulnerable("https://example.com", newResponse(404, body, nil), nil, nil)
	if got.platform != "GitHub Pages" || !strings.Contains(got.err.Error(), "verify manually") {
		t.Errorf("expected labelled GitHub Pages edge case, got %q: %v", got.platform, got.err)
	}
}

func TestRedirectFingerprint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/error.ghost.org/", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("site offline"))
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")
	found := checkResponse(host, nil, []string{"http"}, nil, nil)
	if len(found) != 1 || found[0].platform != "Ghost" {
		t.Fatalf("expected a Ghost issue, got %+v", found)
	}
	if found[0].fqdn != host {
		t.Errorf("expected fqdn %q, got %q", host, found[0].fqdn)
	}
}

func TestWasabiIsNotReportedAsS3(t *testing.T) {
	body := "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message><BucketName>assets.example.com</BucketName></Error>"
	wasabi := http.Header{"Server": []string{"WasabiS3/8.1.333"}}
	if got := checkVulnerable("https://assets.example.com", newResponse(404, body, wasabi), nil, nil); got.platform != "Wasabi" {
		t.Errorf("expected Wasabi, got %q", got.platform)
	}
	if got := checkVulnerable("https://assets.example.com", newResponse(404, body, http.Header{"Server": []string{"AmazonS3"}}), nil, nil); got.platform != "S3" {
		t.Errorf("expected S3, got %q", got.platform)
	}
}
