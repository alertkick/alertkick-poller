package client

import (
	"alertkick-poller/config"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// ErrLeaseConflict is returned from AcquireLease / RenewLease when another
// poller holds the lease (HTTP 409). Callers inspect this to decide whether
// to fall back to follower mode; a generic error would obscure that.
var ErrLeaseConflict = errors.New("poller lease held by another poller")

// Client handles communication with the AlertKick API.
type Client struct {
	httpClient *http.Client
	baseURL    string
	token      string
}

// NewClient creates a new API client.
func NewClient(cfg *config.Config) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: cfg.APIURL + "/api/v1",
		token:   cfg.PollerToken,
	}
}

// RegisterRequest is sent when the poller starts.
type RegisterRequest struct {
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
}

// RegisterResponse is returned from the register endpoint.
type RegisterResponse struct {
	PollerUUID   string `json:"poller_uuid"`
	LocationUUID string `json:"location_uuid"`
	LocationKey  string `json:"location_key"`
	LocationName string `json:"location_name"`
	Type         string `json:"type"`
}

// Register registers this poller with the API.
func (c *Client) Register(hostname, version string) (*RegisterResponse, error) {
	body := RegisterRequest{
		Hostname: hostname,
		Version:  version,
	}

	resp := &RegisterResponse{}
	err := c.doJSON("POST", "/poller/register", body, resp)
	if err != nil {
		return nil, fmt.Errorf("register failed: %w", err)
	}
	return resp, nil
}

// HeartbeatRequest is sent periodically with self-metrics.
type HeartbeatRequest struct {
	PollerUUID         string  `json:"poller_uuid"`
	Status             string  `json:"status"`
	CPUPercent         float64 `json:"cpu_percent"`
	MemoryMB           int64   `json:"memory_mb"`
	QueueDepth         int     `json:"queue_depth"`
	ChecksExecuted     int64   `json:"checks_executed"`
	ChecksPerMinute    float64 `json:"checks_per_minute"`
	AvgCheckDurationMs int64   `json:"avg_check_duration_ms"`
	Errors             int64   `json:"errors"`
	UptimeSeconds      int64   `json:"uptime_seconds"`
	Version            string  `json:"version"`
}

// Heartbeat sends a health report.
func (c *Client) Heartbeat(req *HeartbeatRequest) error {
	return c.doJSON("POST", "/poller/heartbeat", req, nil)
}

// MonitorAssignment is a monitor the poller should check.
type MonitorAssignment struct {
	UUID                     string            `json:"uuid"`
	Subdomain                string            `json:"subdomain"`
	DisplayName              string            `json:"display_name"`
	MonitorType              string            `json:"monitor_type"`
	URL                      string            `json:"url"`
	HTTPMethod               string            `json:"http_method"`
	RequestBody              *string           `json:"request_body,omitempty"`
	Headers                  map[string]string `json:"headers,omitempty"`
	Auth                     *MonitorAuth      `json:"auth,omitempty"`
	TimeoutSeconds           int               `json:"timeout_seconds"`
	CheckIntervalSeconds     int               `json:"check_interval_seconds"`
	ExpectedStatusCode       int               `json:"expected_status_code"`
	ExpectedResponseContains *string           `json:"expected_response_contains,omitempty"`
	DNSRecordType            string            `json:"dns_record_type,omitempty"`
	ExpectedDNSHost          string            `json:"expected_dns_host,omitempty"`
	TCPPort                  int               `json:"tcp_port,omitempty"`
	SSLCertMonitoring        bool              `json:"ssl_cert_monitoring"`
	SSLCertExpiryAlertDays   *int              `json:"ssl_cert_expiry_alert_days,omitempty"`
	DomainExpiryAlertDays    *int              `json:"domain_expiry_alert_days,omitempty"`
	MailRequireDmarcPolicy   string            `json:"mail_require_dmarc_policy,omitempty"`
	FailureThreshold         int               `json:"failure_threshold"`
	Location                 string            `json:"location"`

	// ReceivedAt is stamped by the dispatcher when the assignment arrives
	// (Kafka message timestamp when available). Execution start minus this
	// is the dispatch-lag metric; never serialized.
	ReceivedAt time.Time `json:"-"`
}

// MonitorAuth holds auth config for a monitor.
type MonitorAuth struct {
	Type     string `json:"type"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Token    string `json:"token,omitempty"`
}

// MonitorsResponse is the response from the monitors endpoint.
type MonitorsResponse struct {
	Monitors []MonitorAssignment `json:"monitors"`
	Total    int                 `json:"total"`
}

// GetMonitors fetches monitors assigned to this poller's location.
func (c *Client) GetMonitors() ([]MonitorAssignment, error) {
	resp := &MonitorsResponse{}
	err := c.doJSON("GET", "/poller/monitors", nil, resp)
	if err != nil {
		return nil, fmt.Errorf("get monitors failed: %w", err)
	}
	return resp.Monitors, nil
}

// CheckResult is a single check result to submit.
type CheckResult struct {
	MonitorUUID    string                 `json:"monitor_uuid"`
	Subdomain      string                 `json:"subdomain"`
	Location       string                 `json:"location"`
	PollerUUID     string                 `json:"poller_uuid"`
	CheckedAt      string                 `json:"checked_at"` // RFC3339
	Success        bool                   `json:"success"`
	StatusCode     int                    `json:"status_code,omitempty"`
	ResponseTimeMs int64                  `json:"response_time_ms"`
	ErrorMessage   string                 `json:"error_message,omitempty"`
	ResponseBody   string                 `json:"response_body,omitempty"`
	Details        map[string]interface{} `json:"details,omitempty"`
}

// SubmitResultsRequest is the batch result submission payload.
type SubmitResultsRequest struct {
	PollerUUID string        `json:"poller_uuid"`
	Results    []CheckResult `json:"results"`
}

// SubmitResultsResponse is the response from the results endpoint.
type SubmitResultsResponse struct {
	Accepted int `json:"accepted"`
	Rejected int `json:"rejected"`
}

// SubmitResults sends a batch of check results.
func (c *Client) SubmitResults(pollerUUID string, results []CheckResult) (*SubmitResultsResponse, error) {
	req := SubmitResultsRequest{
		PollerUUID: pollerUUID,
		Results:    results,
	}
	resp := &SubmitResultsResponse{}
	err := c.doJSON("POST", "/poller/results", req, resp)
	if err != nil {
		return nil, fmt.Errorf("submit results failed: %w", err)
	}
	return resp, nil
}

// LeaseRequest identifies the caller on acquire/renew/release calls.
type LeaseRequest struct {
	PollerUUID string `json:"poller_uuid"`
}

// LeaseResponse mirrors apapi's LeaseResponse. On a 409 the LeaderUUID
// field identifies who currently holds the lease — useful for logging.
type LeaseResponse struct {
	LeaderUUID string    `json:"leader_uuid"`
	Term       int64     `json:"term"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// AcquireLease tries to become the active poller at this location. Returns
// ErrLeaseConflict if another poller holds it.
func (c *Client) AcquireLease(pollerUUID string) (*LeaseResponse, error) {
	resp := &LeaseResponse{}
	err := c.doLease("POST", "/poller/lease/acquire", LeaseRequest{PollerUUID: pollerUUID}, resp)
	if err != nil {
		return resp, err
	}
	return resp, nil
}

// RenewLease extends the current lease. Returns ErrLeaseConflict if we've
// lost leadership (failed to renew within the TTL window).
func (c *Client) RenewLease(pollerUUID string) (*LeaseResponse, error) {
	resp := &LeaseResponse{}
	err := c.doLease("POST", "/poller/lease/renew", LeaseRequest{PollerUUID: pollerUUID}, resp)
	if err != nil {
		return resp, err
	}
	return resp, nil
}

// ReleaseLease gives up the lease on graceful shutdown. Best-effort.
func (c *Client) ReleaseLease(pollerUUID string) error {
	return c.doLease("POST", "/poller/lease/release", LeaseRequest{PollerUUID: pollerUUID}, nil)
}

// doLease is like doJSON but maps 409 to ErrLeaseConflict and still decodes
// the body so callers can see who holds it.
func (c *Client) doLease(method, path string, body, result interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequest(method, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("X-Poller-Token", c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AlertKick-Poller/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if result != nil && len(respBody) > 0 {
		_ = json.Unmarshal(respBody, result)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusConflict:
		return ErrLeaseConflict
	default:
		return fmt.Errorf("API %s %s returned %d: %s", method, path, resp.StatusCode, string(respBody))
	}
}

// doJSON performs an HTTP request with JSON body and decodes the JSON response.
func (c *Client) doJSON(method, path string, body interface{}, result interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.baseURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Poller-Token", c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AlertKick-Poller/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		log.Printf("[client] %s %s returned %d: %s", method, path, resp.StatusCode, string(respBody))
		return fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}
