package checker

import (
	"alertkick-poller/client"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

func performDNSCheck(m *client.MonitorAssignment) *Result {
	result := &Result{
		MonitorUUID: m.UUID,
		Subdomain:   m.Subdomain,
		Location:    m.Location,
		CheckedAt:   time.Now().UTC(),
	}

	hostname := m.URL
	hostname = strings.TrimPrefix(hostname, "http://")
	hostname = strings.TrimPrefix(hostname, "https://")
	if idx := strings.Index(hostname, "/"); idx != -1 {
		hostname = hostname[:idx]
	}
	if idx := strings.Index(hostname, ":"); idx != -1 {
		hostname = hostname[:idx]
	}

	timeout := time.Duration(m.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, address)
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()

	recordType := m.DNSRecordType
	if recordType == "" {
		recordType = "A"
	}

	var lookupErr error
	var resolvedAddresses []string

	switch recordType {
	case "A", "AAAA":
		addrs, err := resolver.LookupHost(ctx, hostname)
		lookupErr = err
		resolvedAddresses = addrs
	case "CNAME":
		cname, err := resolver.LookupCNAME(ctx, hostname)
		lookupErr = err
		if cname != "" {
			resolvedAddresses = []string{cname}
		}
	case "MX":
		mxRecords, err := resolver.LookupMX(ctx, hostname)
		lookupErr = err
		for _, mx := range mxRecords {
			resolvedAddresses = append(resolvedAddresses, mx.Host)
		}
	case "TXT":
		txtRecords, err := resolver.LookupTXT(ctx, hostname)
		lookupErr = err
		resolvedAddresses = txtRecords
	case "NS":
		nsRecords, err := resolver.LookupNS(ctx, hostname)
		lookupErr = err
		for _, ns := range nsRecords {
			resolvedAddresses = append(resolvedAddresses, ns.Host)
		}
	default:
		addrs, err := resolver.LookupHost(ctx, hostname)
		lookupErr = err
		resolvedAddresses = addrs
	}

	elapsed := time.Since(start)
	result.ResponseTimeMs = elapsed.Milliseconds()

	if lookupErr != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("DNS lookup failed: %v", lookupErr)
		return result
	}

	if len(resolvedAddresses) == 0 {
		result.Success = false
		result.ErrorMessage = "DNS lookup returned no results"
		return result
	}

	result.ResponseBody = strings.Join(resolvedAddresses, ", ")

	if m.ExpectedDNSHost != "" {
		found := false
		for _, addr := range resolvedAddresses {
			if strings.Contains(addr, m.ExpectedDNSHost) {
				found = true
				break
			}
		}
		if !found {
			result.Success = false
			result.ErrorMessage = fmt.Sprintf("expected DNS host %s not found in results", m.ExpectedDNSHost)
			return result
		}
	}

	result.Success = true
	result.StatusCode = 200
	return result
}
