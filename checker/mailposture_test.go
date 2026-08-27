package checker

import (
	"context"
	"os"
	"testing"
	"time"
)

// Live DNS test; opt in with AK_NET_TESTS=1.
func TestCheckMailPostureLive(t *testing.T) {
	if os.Getenv("AK_NET_TESTS") == "" {
		t.Skip("set AK_NET_TESTS=1 to run live DNS checks")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, domain := range []string{"alertkick.com", "gmail.com", "example.com"} {
		p := CheckMailPosture(ctx, domain, "")
		t.Logf("%s: grade=%s score=%d spf.all=%v lookups=%v dmarc.p=%v dkim=%d wildcard=%v listings=%v fails=%v",
			domain, p.Grade, p.Score, p.SPF["all"], p.SPF["lookups"], p.DMARC["policy"],
			len(p.DKIM["found"].([]map[string]any)), p.DKIM["wildcard"], p.Listings, p.Fails)
		if p.Grade == "" || len(p.Findings) == 0 {
			t.Errorf("%s: empty posture", domain)
		}
	}
	// A required policy stronger than the published one must fail.
	p := CheckMailPosture(ctx, "gmail.com", "reject")
	if len(p.Fails) == 0 {
		t.Errorf("expected gmail.com (p=none) to fail a reject requirement")
	}
}
