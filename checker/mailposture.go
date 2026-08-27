package checker

// Mail posture check for the "mail" monitor type: MX, SPF (recursive lookup
// budget, redirect), DMARC tags, DKIM on common selectors (with a wildcard
// probe), MTA-STS, TLS-RPT and DNSBL listings for every MX address plus the
// Spamhaus DBL for the domain. Stdlib only.
//
// This file is intentionally identical in alertkick-poller/checker and
// alertkick-api/scheduler (only the package line differs). Monitor checks run
// in both places; edit one, copy to the other.

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	mailSPFLookupLimit = 10
	mailMaxMX          = 6
	mailMaxIPs         = 8
)

var mailDKIMSelectors = []string{
	"default", "google", "selector1", "selector2", "k1", "k2", "k3", "mail", "dkim", "s1", "s2",
	"mandrill", "zoho", "protonmail", "protonmail2", "fm1", "fm2", "mailgun", "smtp", "sendgrid", "pm", "mxvault",
}

type mailBlocklist struct {
	Name     string
	Zone     string
	Spamhaus bool
}

var mailIPBlocklists = []mailBlocklist{
	{"Spamhaus ZEN", "zen.spamhaus.org", true},
	{"SpamCop", "bl.spamcop.net", false},
	{"Barracuda", "b.barracudacentral.org", false},
	{"PSBL", "psbl.surriel.com", false},
	{"UCEPROTECT L1", "dnsbl-1.uceprotect.net", false},
}

// MailFinding is one row of the report shown to the user.
type MailFinding struct {
	Severity string `json:"severity"` // fail | warn | info | pass
	Title    string `json:"title"`
	Detail   string `json:"detail"`
}

// MailPosture is the structured outcome persisted as the monitor's mail_info.
type MailPosture struct {
	Domain       string           `json:"domain"`
	Grade        string           `json:"grade"`
	Score        int              `json:"score"`
	Summary      string           `json:"summary"`
	ReceivesMail bool             `json:"receives_mail"`
	MX           []map[string]any `json:"mx"`
	SPF          map[string]any   `json:"spf"`
	DMARC        map[string]any   `json:"dmarc"`
	DKIM         map[string]any   `json:"dkim"`
	MTASTS       map[string]any   `json:"mta_sts"`
	TLSRPT       map[string]any   `json:"tls_rpt"`
	Blocklists   map[string]any   `json:"blocklists"`
	Findings     []MailFinding    `json:"findings"`
	Fails        []string         `json:"-"`
	DMARCPolicy  string           `json:"-"`
	Listings     []string         `json:"-"`
}

// ToDetails converts the posture to the generic details map the check
// result carries over the wire.
func (p *MailPosture) ToDetails() map[string]any {
	findings := make([]any, 0, len(p.Findings))
	for _, f := range p.Findings {
		findings = append(findings, map[string]any{"severity": f.Severity, "title": f.Title, "detail": f.Detail})
	}
	mx := make([]any, 0, len(p.MX))
	for _, m := range p.MX {
		mx = append(mx, m)
	}
	return map[string]any{
		"domain":        p.Domain,
		"grade":         p.Grade,
		"score":         p.Score,
		"summary":       p.Summary,
		"receives_mail": p.ReceivesMail,
		"mx":            mx,
		"spf":           p.SPF,
		"dmarc":         p.DMARC,
		"dkim":          p.DKIM,
		"mta_sts":       p.MTASTS,
		"tls_rpt":       p.TLSRPT,
		"blocklists":    p.Blocklists,
		"findings":      findings,
	}
}

var (
	spfAllRe      = regexp.MustCompile(`(?i)(?:^|\s)([+\-~?]?)all(?:\s|$)`)
	spfRedirectRe = regexp.MustCompile(`(?i)(?:^|\s)redirect=(\S+)`)
	spfIncludeRe  = regexp.MustCompile(`(?i)^(include|redirect)[:=](.+)$`)
	spfLookupRe   = regexp.MustCompile(`(?i)^(a|mx|ptr|exists)(:|/|$)`)
	dkimPRe       = regexp.MustCompile(`(?:^|;)\s*p=([^;]*)`)
	dkimEmptyPRe  = regexp.MustCompile(`p=\s*(;|$)`)
)

// CheckMailPosture runs the full check. requireDmarcPolicy ("", "none",
// "quarantine", "reject") is the minimum DMARC policy the monitor demands;
// weaker (or missing) fails the check.
func CheckMailPosture(ctx context.Context, domain, requireDmarcPolicy string) *MailPosture {
	cf := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, network, "1.1.1.1:53")
	}}
	sys := &net.Resolver{PreferGo: true}

	p := &MailPosture{Domain: domain}
	var wg sync.WaitGroup
	var mxRows []map[string]any
	var nullMX bool
	run := func(f func()) { wg.Add(1); go func() { defer wg.Done(); f() }() }
	run(func() { mxRows, nullMX = mailCheckMX(ctx, cf, domain) })
	run(func() { p.SPF = mailCheckSPF(ctx, cf, domain) })
	run(func() { p.DMARC = mailCheckDMARC(ctx, cf, domain) })
	run(func() { p.DKIM = mailCheckDKIM(ctx, cf, domain) })
	run(func() { p.MTASTS = mailCheckSimpleTXT(ctx, cf, "_mta-sts."+domain, "v=STSv1") })
	run(func() { p.TLSRPT = mailCheckSimpleTXT(ctx, cf, "_smtp._tls."+domain, "v=TLSRPTv1") })
	wg.Wait()
	p.MX = mxRows

	ipSet := map[string]bool{}
	var ips []string
	for _, m := range mxRows {
		for _, ip := range m["ips"].([]string) {
			if !ipSet[ip] {
				ipSet[ip] = true
				ips = append(ips, ip)
			}
		}
	}
	p.Blocklists = mailCheckBlocklists(ctx, sys, domain, ips)

	// ---- scoring --------------------------------------------------------
	score := 100
	add := func(sev, title, detail string) {
		p.Findings = append(p.Findings, MailFinding{sev, title, detail})
		if sev == "fail" {
			p.Fails = append(p.Fails, title)
		}
	}
	p.ReceivesMail = len(mxRows) > 0 && !nullMX

	switch {
	case nullMX:
		add("info", "Null MX published", "This domain declares it does not accept mail (RFC 7505). SPF -all and DMARC p=reject are still needed to stop spoofing.")
	case len(mxRows) == 0:
		add("warn", "No MX records", "The domain does not receive mail. If that is intended, publish \"v=spf1 -all\" and a DMARC p=reject record so nobody can send as it.")
	default:
		parts := make([]string, 0, len(mxRows))
		for _, m := range mxRows {
			parts = append(parts, fmt.Sprintf("%d %s", m["priority"], m["exchange"]))
		}
		add("pass", fmt.Sprintf("%d MX record%s", len(mxRows), plural(len(mxRows))), strings.Join(parts, ", "))
	}

	spf := p.SPF
	if !spf["found"].(bool) {
		score -= 30
		add("fail", "No SPF record", "Receivers cannot tell which servers may send for this domain. Publish a TXT record starting with v=spf1 listing your senders and ending in -all.")
	} else {
		issues := spf["issues"].([]string)
		for _, i := range issues {
			sev := "warn"
			if strings.Contains(i, "PermError") || strings.Contains(i, "+all") || strings.Contains(i, "no SPF record") {
				sev = "fail"
			}
			add(sev, "SPF", i)
		}
		all, _ := spf["all"].(string)
		switch all {
		case "+all":
			score -= 25
		case "?all":
			score -= 10
		case "":
			if !spfRedirectRe.MatchString(spf["record"].(string)) {
				score -= 10
			}
		}
		if spf["lookups"].(int) > mailSPFLookupLimit {
			score -= 15
		}
		if len(spf["records"].([]string)) > 1 {
			score -= 15
		}
		if len(issues) == 0 {
			add("pass", "SPF", fmt.Sprintf("%s with %d/%d DNS lookups.", all, spf["lookups"].(int), mailSPFLookupLimit))
		}
	}

	dm := p.DMARC
	if !dm["found"].(bool) {
		score -= 30
		add("fail", "No DMARC record", fmt.Sprintf("Publish a TXT record at _dmarc.%s. Start with \"v=DMARC1; p=none; rua=mailto:dmarc@%s\" to collect reports, then tighten to quarantine and reject.", domain, domain))
	} else {
		issues := dm["issues"].([]string)
		for _, i := range issues {
			sev := "warn"
			if strings.Contains(i, "Missing required") || strings.Contains(i, "ignore all") {
				sev = "fail"
			}
			add(sev, "DMARC", i)
		}
		pol, _ := dm["policy"].(string)
		p.DMARCPolicy = pol
		switch pol {
		case "":
			score -= 25
		case "none":
			score -= 15
		case "quarantine":
			score -= 5
		}
		if len(dm["rua"].([]string)) == 0 {
			score -= 5
		}
		if pct, ok := dm["pct"].(int); ok && pct < 100 {
			score -= 5
		}
		if len(issues) == 0 {
			add("pass", "DMARC", fmt.Sprintf("p=%s, reports to %s.", pol, strings.Join(dm["rua"].([]string), ", ")))
		}
	}

	dk := p.DKIM
	found := dk["found"].([]map[string]any)
	if len(found) > 0 {
		sels := make([]string, 0, len(found))
		weak := ""
		for _, f := range found {
			sels = append(sels, f["selector"].(string))
			if b, ok := f["key_bits"].(int); ok && b == 1024 {
				weak = " (a 1024-bit key; 2048 is the current recommendation)"
			}
		}
		add("pass", "DKIM", fmt.Sprintf("Public keys found for selector%s %s%s.", plural(len(found)), strings.Join(sels, ", "), weak))
	} else if dk["wildcard"].(bool) {
		rec, _ := dk["wildcard_record"].(string)
		extra := ""
		if dkimEmptyPRe.MatchString(rec) {
			extra = " Its empty p= revokes every unlisted selector, which is a deliberate hardening choice."
		}
		add("info", "DKIM", fmt.Sprintf("A wildcard record under _domainkey.%s answers every selector (%s), so selector probing is meaningless here.%s", domain, rec, extra))
	} else if p.ReceivesMail {
		add("info", "DKIM", fmt.Sprintf("None of %d common selectors answered. Selectors are private, so this is not proof DKIM is missing; check a message header for \"s=\" to confirm.", len(mailDKIMSelectors)))
	}

	if p.ReceivesMail {
		if p.MTASTS["found"].(bool) {
			add("pass", "MTA-STS", "Policy published; senders that support it will refuse to deliver over plaintext.")
		} else {
			add("info", "No MTA-STS", "Optional. Publishing an MTA-STS policy stops downgrade attacks on inbound TLS.")
		}
		if p.TLSRPT["found"].(bool) {
			add("pass", "TLS-RPT", "Reporting address published.")
		} else {
			add("info", "No TLS-RPT", "Optional. A TLS-RPT record gets you reports when senders fail to negotiate TLS with your MX.")
		}
	}

	listings := p.Blocklists["listings"].([]map[string]any)
	if len(listings) > 0 {
		score -= min(40, 20*len(listings))
		for _, l := range listings {
			key := fmt.Sprintf("%s@%s", l["target"], l["list"])
			p.Listings = append(p.Listings, key)
			add("fail", fmt.Sprintf("Listed on %s", l["list"]), fmt.Sprintf("%s returned %s. Mail from this host is likely to be rejected or junked until delisted.", l["target"], strings.Join(l["codes"].([]string), ", ")))
		}
	} else if len(ips) > 0 {
		add("pass", "Blocklists", fmt.Sprintf("%d MX address%s clean on %d DNSBLs; domain not on Spamhaus DBL.", p.Blocklists["ips_checked"].(int), pluralEs(p.Blocklists["ips_checked"].(int)), len(mailIPBlocklists)))
	}
	if errs := p.Blocklists["errors"].([]string); len(errs) > 0 {
		add("info", "Some blocklist queries did not answer", strings.Join(errs[:min(3, len(errs))], " | "))
	}
	sort.Strings(p.Listings)

	// DMARC minimum policy demanded by the monitor.
	if requireDmarcPolicy != "" {
		rank := map[string]int{"": 0, "none": 1, "quarantine": 2, "reject": 3}
		if rank[p.DMARCPolicy] < rank[requireDmarcPolicy] {
			have := p.DMARCPolicy
			if have == "" {
				have = "missing"
			}
			add("fail", "DMARC policy below the required level", fmt.Sprintf("This monitor requires p=%s or stronger; the published policy is %s.", requireDmarcPolicy, have))
		}
	}

	if score < 0 {
		score = 0
	}
	p.Score = score
	p.Grade = mailGrade(score)
	nFail := len(p.Fails)
	switch {
	case nFail > 0:
		p.Summary = fmt.Sprintf("%d problem%s that will cost deliverability or let this domain be spoofed.", nFail, plural(nFail))
	case hasSeverity(p.Findings, "warn"):
		p.Summary = "Basics are in place; the warnings are the next steps."
	default:
		p.Summary = "SPF, DMARC and blocklists all look good."
	}
	return p
}

func mailGrade(score int) string {
	switch {
	case score >= 95:
		return "A+"
	case score >= 85:
		return "A"
	case score >= 70:
		return "B"
	case score >= 55:
		return "C"
	case score >= 40:
		return "D"
	}
	return "F"
}

func hasSeverity(fs []MailFinding, sev string) bool {
	for _, f := range fs {
		if f.Severity == sev {
			return true
		}
	}
	return false
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func pluralEs(n int) string {
	if n == 1 {
		return ""
	}
	return "es"
}

func mailTXT(ctx context.Context, r *net.Resolver, name string) []string {
	rows, err := r.LookupTXT(ctx, name)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(rows))
	for _, t := range rows {
		out = append(out, strings.TrimSpace(t))
	}
	return out
}

func mailFindSPF(txts []string) string {
	for _, t := range txts {
		if l := strings.ToLower(t); l == "v=spf1" || strings.HasPrefix(l, "v=spf1 ") {
			return t
		}
	}
	return ""
}

func mailCheckMX(ctx context.Context, r *net.Resolver, domain string) ([]map[string]any, bool) {
	mxs, err := r.LookupMX(ctx, domain)
	if err != nil || len(mxs) == 0 {
		return nil, false
	}
	sort.Slice(mxs, func(i, j int) bool { return mxs[i].Pref < mxs[j].Pref })
	if len(mxs) > mailMaxMX {
		mxs = mxs[:mailMaxMX]
	}
	if len(mxs) == 1 && strings.Trim(mxs[0].Host, ".") == "" {
		return []map[string]any{{"priority": int(mxs[0].Pref), "exchange": "", "ips": []string{}}}, true
	}
	rows := make([]map[string]any, len(mxs))
	var wg sync.WaitGroup
	for i, m := range mxs {
		wg.Add(1)
		go func(i int, m *net.MX) {
			defer wg.Done()
			host := strings.ToLower(strings.TrimSuffix(m.Host, "."))
			ips := []string{}
			if host != "" {
				if addrs, err := r.LookupIP(ctx, "ip4", host); err == nil {
					for _, a := range addrs {
						if len(ips) < 4 {
							ips = append(ips, a.String())
						}
					}
				}
			}
			rows[i] = map[string]any{"priority": int(m.Pref), "exchange": host, "ips": ips}
		}(i, m)
	}
	wg.Wait()
	return rows, false
}

func mailCheckSPF(ctx context.Context, r *net.Resolver, domain string) map[string]any {
	var records []string
	for _, t := range mailTXT(ctx, r, domain) {
		if l := strings.ToLower(t); l == "v=spf1" || strings.HasPrefix(l, "v=spf1 ") {
			records = append(records, t)
		}
	}
	out := map[string]any{"found": len(records) > 0, "record": "", "records": records, "all": "", "lookups": 0, "lookup_limit": mailSPFLookupLimit, "issues": []string{}}
	if len(records) == 0 {
		return out
	}
	record := records[0]
	out["record"] = record
	issues := []string{}
	if len(records) > 1 {
		issues = append(issues, fmt.Sprintf("%d SPF records published - receivers treat this as a permanent error (PermError) and ignore SPF entirely.", len(records)))
	}
	if len(record) > 255 {
		issues = append(issues, "Record is longer than 255 characters; make sure it is split into multiple strings in the TXT record.")
	}

	seen := map[string]bool{}
	var count func(name, rec string, depth int) int
	count = func(name, rec string, depth int) int {
		n := 0
		for _, term := range strings.Fields(rec)[1:] {
			t := strings.ToLower(strings.TrimLeft(term, "+-~?"))
			if spfLookupRe.MatchString(t) {
				n++
			}
			if m := spfIncludeRe.FindStringSubmatch(t); m != nil {
				n++
				target := strings.ReplaceAll(m[2], "%{d}", name)
				if depth < 6 && !seen[target] && n <= 30 {
					seen[target] = true
					if sub := mailFindSPF(mailTXT(ctx, r, target)); sub != "" {
						n += count(target, sub, depth+1)
					} else {
						issues = append(issues, fmt.Sprintf("include:%s has no SPF record (counts as a lookup, and the include fails).", target))
					}
				}
			}
			if t == "ptr" || strings.HasPrefix(t, "ptr:") {
				issues = append(issues, "ptr mechanism is deprecated (RFC 7208) and slow; replace it with ip4/ip6 or include.")
			}
		}
		return n
	}
	lookups := count(domain, record, 0)
	out["lookups"] = lookups
	if lookups > mailSPFLookupLimit {
		issues = append(issues, fmt.Sprintf("%d DNS lookups, over the limit of %d. Receivers return PermError and ignore the record. Flatten includes or drop unused senders.", lookups, mailSPFLookupLimit))
	}

	allMatch := spfAllRe.FindStringSubmatch(record)
	if allMatch == nil {
		if rm := spfRedirectRe.FindStringSubmatch(record); rm != nil {
			if target := mailFindSPF(mailTXT(ctx, r, strings.ReplaceAll(rm[1], "%{d}", domain))); target != "" {
				allMatch = spfAllRe.FindStringSubmatch(target)
			}
		}
	}
	if allMatch != nil {
		q := allMatch[1]
		if q == "" {
			q = "+"
		}
		out["all"] = q + "all"
		switch q {
		case "+":
			issues = append(issues, "+all lets anyone send as this domain. Use -all or ~all.")
		case "?":
			issues = append(issues, "?all is neutral and gives receivers nothing to act on. Use -all or ~all.")
		}
	} else if !spfRedirectRe.MatchString(record) {
		issues = append(issues, "No \"all\" mechanism - the record never reaches a verdict for unlisted senders. End it with -all or ~all.")
	}
	out["issues"] = issues
	return out
}

func mailCheckDMARC(ctx context.Context, r *net.Resolver, domain string) map[string]any {
	var recs []string
	for _, t := range mailTXT(ctx, r, "_dmarc."+domain) {
		if strings.HasPrefix(strings.ToLower(t), "v=dmarc1") {
			recs = append(recs, t)
		}
	}
	out := map[string]any{"found": len(recs) > 0, "record": "", "policy": "", "subdomain_policy": "", "pct": 100, "rua": []string{}, "ruf": []string{}, "adkim": "r", "aspf": "r", "issues": []string{}}
	if len(recs) == 0 {
		return out
	}
	record := recs[0]
	out["record"] = record
	issues := []string{}
	if len(recs) > 1 {
		issues = append(issues, fmt.Sprintf("%d DMARC records published - receivers ignore all of them. Keep one.", len(recs)))
	}
	tags := map[string]string{}
	for _, part := range strings.Split(record, ";") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			tags[strings.ToLower(strings.TrimSpace(kv[0]))] = strings.TrimSpace(kv[1])
		}
	}
	split := func(s string) []string {
		if s == "" {
			return []string{}
		}
		parts := strings.Split(s, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		return parts
	}
	policy := strings.ToLower(tags["p"])
	out["policy"] = policy
	out["subdomain_policy"] = strings.ToLower(tags["sp"])
	pct := 100
	if v, ok := tags["pct"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			pct = n
		}
	}
	out["pct"] = pct
	rua := split(tags["rua"])
	out["rua"] = rua
	out["ruf"] = split(tags["ruf"])
	if v := strings.ToLower(tags["adkim"]); v != "" {
		out["adkim"] = v
	}
	if v := strings.ToLower(tags["aspf"]); v != "" {
		out["aspf"] = v
	}

	switch policy {
	case "":
		issues = append(issues, "Missing required p= tag; receivers treat the record as invalid.")
	case "none":
		issues = append(issues, "p=none only reports; spoofed mail is still delivered. Move to p=quarantine, then p=reject, once reports look clean.")
	case "quarantine":
		issues = append(issues, "p=quarantine sends spoofed mail to spam rather than rejecting it. p=reject is the end state.")
	}
	if pct < 100 {
		issues = append(issues, fmt.Sprintf("pct=%d: the policy applies to only %d%% of failing mail.", pct, pct))
	}
	if len(rua) == 0 {
		issues = append(issues, "No rua= address - you receive no aggregate reports and cannot see who is sending as this domain.")
	}
	if out["subdomain_policy"] == "none" && policy != "none" {
		issues = append(issues, "sp=none leaves every subdomain open to spoofing even though the apex is protected.")
	}
	out["issues"] = issues
	return out
}

func mailIsDKIM(t string) bool {
	return regexp.MustCompile(`(?i)(^|;|\s)v=DKIM1`).MatchString(t) || regexp.MustCompile(`(^|;|\s)p=`).MatchString(t)
}

func mailCheckDKIM(ctx context.Context, r *net.Resolver, domain string) map[string]any {
	found := []map[string]any{}
	out := map[string]any{"checked_selectors": len(mailDKIMSelectors), "found": found, "wildcard": false, "wildcard_record": ""}

	probe := mailTXT(ctx, r, fmt.Sprintf("akprobe-%06d._domainkey.%s", rand.Intn(1000000), domain))
	for _, t := range probe {
		if mailIsDKIM(t) {
			out["wildcard"] = true
			out["wildcard_record"] = t
			return out
		}
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, sel := range mailDKIMSelectors {
		wg.Add(1)
		go func(sel string) {
			defer wg.Done()
			for _, t := range mailTXT(ctx, r, sel+"._domainkey."+domain) {
				if !mailIsDKIM(t) {
					continue
				}
				p := ""
				if m := dkimPRe.FindStringSubmatch(t); m != nil {
					p = strings.Join(strings.Fields(m[1]), "")
				}
				if p == "" {
					return // revoked key
				}
				row := map[string]any{"selector": sel, "record": t}
				if len(t) > 120 {
					row["record"] = t[:117] + "..."
				}
				if der, err := base64.StdEncoding.DecodeString(p); err == nil {
					switch {
					case len(der) > 200:
						row["key_bits"] = 2048
					case len(der) > 100:
						row["key_bits"] = 1024
					}
				}
				mu.Lock()
				found = append(found, row)
				mu.Unlock()
				return
			}
		}(sel)
	}
	wg.Wait()
	sort.Slice(found, func(i, j int) bool { return found[i]["selector"].(string) < found[j]["selector"].(string) })
	out["found"] = found
	return out
}

func mailCheckSimpleTXT(ctx context.Context, r *net.Resolver, name, prefix string) map[string]any {
	for _, t := range mailTXT(ctx, r, name) {
		if strings.HasPrefix(strings.ToLower(t), strings.ToLower(prefix)) {
			return map[string]any{"found": true, "record": t}
		}
	}
	return map[string]any{"found": false, "record": ""}
}

func mailReverseV4(ip string) string {
	parts := strings.Split(ip, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, ".")
}

// mailDNSBLQuery returns the A answers for a DNSBL name; a not-found answer
// means "not listed" and is not an error.
func mailDNSBLQuery(ctx context.Context, r *net.Resolver, name string) ([]string, error) {
	qctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	addrs, err := r.LookupIP(qctx, "ip4", name)
	if err != nil {
		var dnsErr *net.DNSError
		if ok := asDNSError(err, &dnsErr); ok && dnsErr.IsNotFound {
			return nil, nil
		}
		return nil, err
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	sort.Strings(out)
	return out, nil
}

func asDNSError(err error, target **net.DNSError) bool {
	for err != nil {
		if d, ok := err.(*net.DNSError); ok {
			*target = d
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func mailCheckBlocklists(ctx context.Context, r *net.Resolver, domain string, ips []string) map[string]any {
	if len(ips) > mailMaxIPs {
		ips = ips[:mailMaxIPs]
	}
	listings := []map[string]any{}
	errs := []string{}
	errSeen := map[string]bool{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	addErr := func(list, msg string) {
		key := list + ": " + msg
		mu.Lock()
		if !errSeen[key] {
			errSeen[key] = true
			errs = append(errs, key)
		}
		mu.Unlock()
	}
	query := func(target, list, name string, spamhaus bool) {
		defer wg.Done()
		codes, err := mailDNSBLQuery(ctx, r, name)
		if err != nil {
			addErr(list, "lookup failed")
			return
		}
		var real []string
		for _, c := range codes {
			if spamhaus && strings.HasPrefix(c, "127.255.255.") {
				addErr(list, fmt.Sprintf("Spamhaus refused the query (%s); the resolver in use is not allowed", c))
				continue
			}
			real = append(real, c)
		}
		if len(real) > 0 {
			mu.Lock()
			listings = append(listings, map[string]any{"target": target, "list": list, "codes": real})
			mu.Unlock()
		}
	}
	for _, ip := range ips {
		if net.ParseIP(ip) == nil || net.ParseIP(ip).To4() == nil {
			continue
		}
		for _, bl := range mailIPBlocklists {
			wg.Add(1)
			go query(ip, bl.Name, mailReverseV4(ip)+"."+bl.Zone, bl.Spamhaus)
		}
	}
	wg.Add(1)
	go query(domain, "Spamhaus DBL", domain+".dbl.spamhaus.org", true)
	wg.Wait()
	sort.Slice(listings, func(i, j int) bool {
		return listings[i]["target"].(string)+listings[i]["list"].(string) < listings[j]["target"].(string)+listings[j]["list"].(string)
	})
	lists := make([]string, 0, len(mailIPBlocklists)+1)
	for _, b := range mailIPBlocklists {
		lists = append(lists, b.Name)
	}
	lists = append(lists, "Spamhaus DBL")
	return map[string]any{"ips_checked": len(ips), "lists": lists, "listings": listings, "errors": errs}
}
