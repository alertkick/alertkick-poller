package checker

import (
	"alertkick-poller/client"
	"context"
	"fmt"
	"strings"
	"time"
)

// performMailCheck runs the mail posture check (MX, SPF, DMARC, DKIM,
// MTA-STS, TLS-RPT, DNSBLs) for a "mail" monitor. The check fails when any
// finding is a hard failure (no SPF, no DMARC, +all, PermError, a blocklist
// listing, or a DMARC policy weaker than the monitor requires). The full
// report travels in Details for the API to persist as mail_info.
func performMailCheck(m *client.MonitorAssignment) *Result {
	result := &Result{
		MonitorUUID: m.UUID,
		Subdomain:   m.Subdomain,
		Location:    m.Location,
		CheckedAt:   time.Now().UTC(),
	}

	domain := normalizeDomain(m.URL)
	if domain == "" {
		result.Success = false
		result.ErrorMessage = "no domain configured"
		return result
	}

	timeout := time.Duration(m.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	posture := CheckMailPosture(ctx, domain, m.MailRequireDmarcPolicy)
	result.ResponseTimeMs = time.Since(start).Milliseconds()
	result.Details = posture.ToDetails()
	result.ResponseBody = fmt.Sprintf("Mail posture for %s: grade %s (%d/100). %s", domain, posture.Grade, posture.Score, posture.Summary)

	if len(posture.Fails) > 0 {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("mail posture for %s: %s", domain, strings.Join(posture.Fails, "; "))
		return result
	}
	result.Success = true
	result.StatusCode = 200
	return result
}
