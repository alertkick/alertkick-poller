package checker

import (
	"alertkick-poller/client"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// rdapBootstrapURL is the IANA-backed RDAP redirector: it 302s to the
// authoritative registry RDAP server for the domain's TLD, so we don't
// need a local copy of the bootstrap registry.
const rdapBootstrapURL = "https://rdap.org/domain/"

const defaultDomainExpiryAlertDays = 30

// dnsProfileTimeout bounds the best-effort DNS/mail profile lookups that
// enrich the domain check; they never fail the check.
const dnsProfileTimeout = 10 * time.Second

// rdapInfo is what we extract from the registry's RDAP record.
type rdapInfo struct {
	Expiry          *time.Time
	RegisteredDate  string
	LastChangedDate string
	Registrar       string
	RegistrarIANAID string
	Statuses        []string
	Nameservers     []string
}

// transferLocked reports whether the registry lists a transfer prohibition
// (RFC 8056 values like "client transfer prohibited"); an unlocked domain
// can be hijacked via a forged transfer request, so we surface it.
func (i *rdapInfo) transferLocked() bool {
	for _, s := range i.Statuses {
		norm := strings.ReplaceAll(strings.ToLower(s), " ", "")
		if strings.Contains(norm, "transferprohibited") {
			return true
		}
	}
	return false
}

// performDomainExpiryCheck looks up the domain's registration via RDAP and
// fails the check when the expiry is inside the alert window. Unlike the
// other checks this is about the registration itself, not reachability —
// the URL field carries a bare domain (example.com). Alongside the
// pass/fail it collects registration details (registrar, transfer lock,
// nameservers) and a DNS/mail profile (apex/www targets, MX, SPF, DMARC)
// into result.Details for display.
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
	info, err := fetchRDAPInfo(domain, timeout)
	result.ResponseTimeMs = time.Since(start).Milliseconds()

	if err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("domain expiry lookup failed: %v", err)
		return result
	}

	daysRemaining := int(time.Until(*info.Expiry).Hours() / 24)
	result.ResponseBody = fmt.Sprintf("Domain %s expires in %d days (on %s)",
		domain, daysRemaining, info.Expiry.Format("2006-01-02"))
	result.Details = buildDomainDetails(domain, info, daysRemaining)

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

// buildDomainDetails merges the RDAP registration info with a best-effort
// DNS/mail profile into the details payload persisted by the API.
func buildDomainDetails(domain string, info *rdapInfo, daysRemaining int) map[string]interface{} {
	details := map[string]interface{}{
		"domain":          domain,
		"expiry_date":     info.Expiry.Format(time.RFC3339),
		"days_remaining":  daysRemaining,
		"transfer_locked": info.transferLocked(),
	}
	if info.Registrar != "" {
		details["registrar"] = info.Registrar
	}
	if info.RegistrarIANAID != "" {
		details["registrar_iana_id"] = info.RegistrarIANAID
	}
	if len(info.Statuses) > 0 {
		details["statuses"] = info.Statuses
	}
	if info.RegisteredDate != "" {
		details["registered_date"] = info.RegisteredDate
	}
	if info.LastChangedDate != "" {
		details["last_changed_date"] = info.LastChangedDate
	}
	if len(info.Nameservers) > 0 {
		details["nameservers"] = info.Nameservers
	}
	for k, v := range collectDNSProfile(domain) {
		details[k] = v
	}
	return details
}

// collectDNSProfile gathers what the domain's DNS says about where it
// points and how mail is set up: apex + www targets, MX records, SPF and
// DMARC policies. Every lookup is best-effort — a missing record simply
// leaves its key out.
func collectDNSProfile(domain string) map[string]interface{} {
	profile := map[string]interface{}{}
	resolver := &net.Resolver{PreferGo: true}
	ctx, cancel := context.WithTimeout(context.Background(), dnsProfileTimeout)
	defer cancel()

	if ips, err := resolver.LookupHost(ctx, domain); err == nil && len(ips) > 0 {
		sort.Strings(ips)
		profile["apex_ips"] = ips
	}

	www := "www." + domain
	if cname, err := resolver.LookupCNAME(ctx, www); err == nil {
		cname = strings.TrimSuffix(cname, ".")
		if cname != "" && !strings.EqualFold(cname, www) {
			profile["www_target"] = cname
		}
	}
	if ips, err := resolver.LookupHost(ctx, www); err == nil && len(ips) > 0 {
		sort.Strings(ips)
		profile["www_ips"] = ips
	}

	if mxs, err := resolver.LookupMX(ctx, domain); err == nil && len(mxs) > 0 {
		records := make([]string, 0, len(mxs))
		for _, mx := range mxs {
			records = append(records, fmt.Sprintf("%d %s", mx.Pref, strings.TrimSuffix(mx.Host, ".")))
		}
		profile["mx_records"] = records
	}

	if txts, err := resolver.LookupTXT(ctx, domain); err == nil {
		for _, txt := range txts {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=spf1") {
				profile["spf_record"] = strings.TrimSpace(txt)
				break
			}
		}
	}

	if txts, err := resolver.LookupTXT(ctx, "_dmarc."+domain); err == nil {
		for _, txt := range txts {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=dmarc1") {
				profile["dmarc_record"] = strings.TrimSpace(txt)
				break
			}
		}
	}

	return profile
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

// fetchRDAPInfo queries RDAP and extracts the registration expiry (required
// — its absence is an error) plus registrar, status, nameserver and event
// details (all optional).
func fetchRDAPInfo(domain string, timeout time.Duration) (*rdapInfo, error) {
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

	var rdap rdapDomainResponse
	if err := json.Unmarshal(body, &rdap); err != nil {
		return nil, fmt.Errorf("invalid RDAP response: %v", err)
	}

	info := &rdapInfo{Statuses: rdap.Status}

	for _, ev := range rdap.Events {
		switch ev.EventAction {
		case "expiration":
			t, err := time.Parse(time.RFC3339, ev.EventDate)
			if err != nil {
				return nil, fmt.Errorf("unparseable expiration date %q: %v", ev.EventDate, err)
			}
			info.Expiry = &t
		case "registration":
			info.RegisteredDate = ev.EventDate
		case "last changed":
			info.LastChangedDate = ev.EventDate
		}
	}
	if info.Expiry == nil {
		return nil, fmt.Errorf("registry did not report an expiration date (some ccTLDs don't publish it over RDAP)")
	}

	for _, ns := range rdap.Nameservers {
		if name := strings.ToLower(strings.TrimSuffix(ns.LdhName, ".")); name != "" {
			info.Nameservers = append(info.Nameservers, name)
		}
	}
	sort.Strings(info.Nameservers)

	info.Registrar, info.RegistrarIANAID = findRegistrar(rdap.Entities)

	return info, nil
}

// rdapDomainResponse is the subset of the RDAP domain object we consume.
type rdapDomainResponse struct {
	Status []string `json:"status"`
	Events []struct {
		EventAction string `json:"eventAction"`
		EventDate   string `json:"eventDate"`
	} `json:"events"`
	Nameservers []struct {
		LdhName string `json:"ldhName"`
	} `json:"nameservers"`
	Entities []rdapEntity `json:"entities"`
}

type rdapEntity struct {
	Roles      []string      `json:"roles"`
	VcardArray []interface{} `json:"vcardArray"`
	PublicIDs  []struct {
		Type       string `json:"type"`
		Identifier string `json:"identifier"`
	} `json:"publicIds"`
	Entities []rdapEntity `json:"entities"`
}

// findRegistrar walks the RDAP entity tree for the entity holding the
// "registrar" role and returns its display name (vCard "fn") and IANA
// registrar ID.
func findRegistrar(entities []rdapEntity) (name, ianaID string) {
	for _, e := range entities {
		isRegistrar := false
		for _, role := range e.Roles {
			if strings.EqualFold(role, "registrar") {
				isRegistrar = true
				break
			}
		}
		if isRegistrar {
			name = vcardFullName(e.VcardArray)
			for _, id := range e.PublicIDs {
				if strings.EqualFold(id.Type, "IANA Registrar ID") {
					ianaID = id.Identifier
				}
			}
			if name != "" || ianaID != "" {
				return name, ianaID
			}
		}
		if n, id := findRegistrar(e.Entities); n != "" || id != "" {
			return n, id
		}
	}
	return "", ""
}

// vcardFullName pulls the "fn" property out of a jCard array
// (["vcard", [["fn", {}, "text", "Registrar Name"], ...]]).
func vcardFullName(vcard []interface{}) string {
	if len(vcard) < 2 {
		return ""
	}
	props, ok := vcard[1].([]interface{})
	if !ok {
		return ""
	}
	for _, p := range props {
		prop, ok := p.([]interface{})
		if !ok || len(prop) < 4 {
			continue
		}
		if key, ok := prop[0].(string); !ok || !strings.EqualFold(key, "fn") {
			continue
		}
		if val, ok := prop[3].(string); ok && val != "" {
			return val
		}
	}
	return ""
}
