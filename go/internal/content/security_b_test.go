package content

import "testing"

// SR-63 (server-name catalog): a normalized server name maps only by label-boundary suffix, the longest suffix
// winning; a name that merely ends with a catalog string, a parent of a catalog name and a vendor's web front map to
// no service (the reference's application_for_host answers).
func TestSecurityServerNameCatalogMatchesOnLabelBoundariesLongestFirst(t *testing.T) {
	p, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]string{
		"youtube.com": "youtube", "rr3---sn-abc.googlevideo.com": "youtube", "teams.microsoft.com": "ms-teams",
		"eu.teams.microsoft.com": "ms-teams", "mail.google.com": "gmail", "www.google.com": "google-base", "microsoft.com": "ms-base",
		"copilot.microsoft.com": "ms-copilot", "mail.yahoo.com": "yahoo-mail", "news.yahoo.com": "yahoo", "api.nordvpn.com": "nordvpn",
		"www.nordvpn.com": "", "notyoutube.com": "", "youtube.com.example.net": "", "example.org": "", "com": "", "googlevideo.co": "",
		"notx.ai": "", "qq.com": "",
	} {
		if got := p.ApplicationForHost(host); got != want {
			t.Errorf("%s: %q, want %q", host, got, want)
		}
	}
}
