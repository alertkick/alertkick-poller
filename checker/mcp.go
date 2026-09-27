package checker

import (
	"alertkick-poller/client"
	"context"
	"encoding/json"
	"strings"
	"time"
)

// performMCPCheck runs the MCP server check for an "mcp" monitor: handshake,
// tool listing, drift against the approved baseline, poison lint, or (auth
// mode "oauth") the discovery chain only. The full report travels in Details
// for the API to persist as mcp_info.
func performMCPCheck(m *client.MonitorAssignment) *Result {
	result := &Result{
		MonitorUUID: m.UUID,
		Subdomain:   m.Subdomain,
		Location:    m.Location,
		CheckedAt:   time.Now().UTC(),
	}

	var baseline *MCPBaseline
	if len(m.McpBaseline) > 0 && string(m.McpBaseline) != "null" {
		baseline = &MCPBaseline{}
		if err := json.Unmarshal(m.McpBaseline, baseline); err != nil {
			result.Success = false
			result.ErrorMessage = "invalid mcp baseline in assignment: " + err.Error()
			return result
		}
	}

	timeout := time.Duration(m.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	report := CheckMCP(ctx, MCPCheckConfig{
		Endpoint:      strings.TrimSpace(m.URL),
		Transport:     m.McpTransport,
		AuthMode:      m.McpAuthMode,
		Headers:       m.McpHeaders,
		DriftPolicy:   m.McpDriftPolicy,
		ExpectedTools: m.McpExpectedTools,
		MaxTools:      m.McpMaxTools,
		Baseline:      baseline,
	})
	result.ResponseTimeMs = time.Since(start).Milliseconds()
	result.Details = report.ToDetails()
	result.ResponseBody = report.Summary()

	if len(report.Fails) > 0 {
		result.Success = false
		result.ErrorMessage = strings.Join(report.Fails, "; ")
		return result
	}
	result.Success = true
	result.StatusCode = 200
	return result
}
