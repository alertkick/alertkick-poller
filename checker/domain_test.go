package checker

import "testing"

// RDAP only knows registered domains: www.shohag.dev returned 400 and
// www.shohag.me 404 on a real signup (2026-09-29).
func TestRDAPLookupUsesRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"www.shohag.dev":                   "shohag.dev",
		"www.shohag.me":                    "shohag.me",
		"https://blog.example.com/path":    "example.com",
		"WWW.Example.CO.UK:443":            "example.co.uk",
		"example.com":                      "example.com",
		"example.com.":                     "example.com",
		"http://deep.sub.example.io/x?y=1": "example.io",
	}
	for in, want := range cases {
		if got := registrableDomain(normalizeDomain(in)); got != want {
			t.Errorf("registrableDomain(normalizeDomain(%q)) = %q, want %q", in, got, want)
		}
	}
}

func TestRegistrableDomainFallsBackOnBareSuffix(t *testing.T) {
	// A bare public suffix has no registrable part; pass it through so the
	// RDAP error reaches the user instead of an empty lookup.
	if got := registrableDomain("co.uk"); got != "co.uk" {
		t.Errorf("registrableDomain(co.uk) = %q", got)
	}
}
