package subtocheck

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestDanglingCNAME(t *testing.T) {
	cases := []struct {
		target   string
		kind     string
		platform string
	}{
		{"old-app.azurewebsites.net", "vuln", "Azure"},
		{"myapp.eastus.cloudapp.azure.com", "vuln", "Azure"},
		{"env.eu-west-1.elasticbeanstalk.com", "vuln", "AWS Elastic Beanstalk"},
		{"forum.trydiscourse.com", "vuln", "Discourse"},
		// only a suffix at a label boundary counts
		{"notazurewebsites.net", "dns", ""},
		{"gone.example.org", "dns", ""},
	}
	for _, c := range cases {
		got := danglingCNAMEIssue("app.example.com", c.target, func(string) registration { return registration{status: statusDelegated} })
		if got.kind != c.kind || got.platform != c.platform {
			t.Errorf("%s: expected %s/%q, got %s/%q", c.target, c.kind, c.platform, got.kind, got.platform)
		}
	}
}

func TestCNAMETargets(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "app.example.com.", Rrtype: dns.TypeCNAME}, Target: "App.AzureWebsites.net."},
		&dns.CNAME{Hdr: dns.RR_Header{Name: "app.azurewebsites.net.", Rrtype: dns.TypeCNAME}, Target: "waws-prod.cloudapp.net."},
		&dns.A{Hdr: dns.RR_Header{Name: "waws-prod.cloudapp.net.", Rrtype: dns.TypeA}},
	}
	got := cnameTargets(msg)
	want := []string{"app.azurewebsites.net", "waws-prod.cloudapp.net"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("expected %v, got %v", want, got)
	}
}
