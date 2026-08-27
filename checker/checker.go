package checker

import (
	"alertkick-poller/client"
	"time"
)

const maxResponseBodySize = 10 * 1024 // 10KB

// Result is the outcome of a single check execution.
type Result struct {
	MonitorUUID    string
	Subdomain      string
	Location       string
	CheckedAt      time.Time
	Success        bool
	StatusCode     int
	ResponseTimeMs int64
	ErrorMessage   string
	ResponseBody   string
	// Details carries check-type-specific structured data (domain registration
	// info, resolved DNS answers) that the API persists on the monitor for
	// display; nil for check types that don't produce any.
	Details map[string]interface{}
}

// Execute runs the appropriate check based on monitor type.
func Execute(m *client.MonitorAssignment, tlsInsecure bool) *Result {
	result := &Result{
		MonitorUUID: m.UUID,
		Subdomain:   m.Subdomain,
		Location:    m.Location,
		CheckedAt:   time.Now().UTC(),
	}

	switch m.MonitorType {
	case "http", "api":
		return performHTTPCheck(m, tlsInsecure)
	case "dns":
		return performDNSCheck(m)
	case "tcp":
		return performTCPCheck(m)
	case "ssl":
		return performSSLCheck(m)
	case "domain":
		return performDomainExpiryCheck(m)
	case "mail":
		return performMailCheck(m)
	default:
		result.Success = false
		result.ErrorMessage = "unknown monitor type: " + m.MonitorType
		return result
	}
}

// ToClientResult converts a Result to a client.CheckResult for API submission.
func (r *Result) ToClientResult(pollerUUID string) client.CheckResult {
	return client.CheckResult{
		MonitorUUID:    r.MonitorUUID,
		Subdomain:      r.Subdomain,
		Location:       r.Location,
		PollerUUID:     pollerUUID,
		CheckedAt:      r.CheckedAt.Format(time.RFC3339),
		Success:        r.Success,
		StatusCode:     r.StatusCode,
		ResponseTimeMs: r.ResponseTimeMs,
		ErrorMessage:   r.ErrorMessage,
		ResponseBody:   r.ResponseBody,
		Details:        r.Details,
	}
}
