package checker

import (
	"alertkick-poller/client"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// rdapBootstrapURL is the IANA-backed RDAP redirector: it 302s to the
// authoritative registry RDAP server for the domain's TLD, so we don't
// need a local copy of the bootstrap registry.
const rdapBootstrapURL = "https://rdap.org/domain/"

const defaultDomainExpiryAlertDays = 30

// performDomainExpiryCheck looks up the domain's registration expiry via
// RDAP and fails the check when it is inside the alert window. Unlike the
// other checks this is about the registration itself, not reachability —
// the URL field carries a bare domain (example.com).
func performDomainExpiryCheck(m *client.MonitorAssignment) *Result {
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

	start := time.Now()
	expiry, err := fetchRDAPExpiry(domain, timeout)
	result.ResponseTimeMs = time.Since(start).Milliseconds()

	if err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("domain expiry lookup failed: %v", err)
		return result
	}

	daysRemaining := int(time.Until(*expiry).Hours() / 24)
	result.ResponseBody = fmt.Sprintf("Domain %s expires in %d days (on %s)",
		domain, daysRemaining, expiry.Format("2006-01-02"))

	alertDays := defaultDomainExpiryAlertDays
	if m.DomainExpiryAlertDays != nil && *m.DomainExpiryAlertDays > 0 {
		alertDays = *m.DomainExpiryAlertDays
	}
	if daysRemaining <= alertDays {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("domain %s expires in %d days (threshold: %d days)",
			domain, daysRemaining, alertDays)
		return result
	}

	result.Success = true
	result.StatusCode = 200
	return result
}

// normalizeDomain reduces whatever the user typed (URL, host:port, bare
// domain) to the registrable name RDAP expects.
func normalizeDomain(raw string) string {
	d := strings.TrimSpace(strings.ToLower(raw))
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	if idx := strings.Index(d, "/"); idx != -1 {
		d = d[:idx]
	}
	if idx := strings.Index(d, ":"); idx != -1 {
		d = d[:idx]
	}
	return strings.Trim(d, ".")
}

// fetchRDAPExpiry queries RDAP and returns the registration expiration
// event date.
func fetchRDAPExpiry(domain string, timeout time.Duration) (*time.Time, error) {
	httpClient := &http.Client{Timeout: timeout}

	req, err := http.NewRequest("GET", rdapBootstrapURL+domain, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/rdap+json")
	req.Header.Set("User-Agent", "AlertKick-Monitor/1.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("domain not found in registry (RDAP 404)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RDAP server returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, err
	}

	var rdap struct {
		Events []struct {
			EventAction string `json:"eventAction"`
			EventDate   string `json:"eventDate"`
		} `json:"events"`
	}
	if err := json.Unmarshal(body, &rdap); err != nil {
		return nil, fmt.Errorf("invalid RDAP response: %v", err)
	}

	for _, ev := range rdap.Events {
		if ev.EventAction != "expiration" {
			continue
		}
		t, err := time.Parse(time.RFC3339, ev.EventDate)
		if err != nil {
			return nil, fmt.Errorf("unparseable expiration date %q: %v", ev.EventDate, err)
		}
		return &t, nil
	}

	return nil, fmt.Errorf("registry did not report an expiration date (some ccTLDs don't publish it over RDAP)")
}
