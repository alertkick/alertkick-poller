package checker

import (
	"alertkick-poller/client"
	"fmt"
	"net"
	"strings"
	"time"
)

func performTCPCheck(m *client.MonitorAssignment) *Result {
	result := &Result{
		MonitorUUID: m.UUID,
		Subdomain:   m.Subdomain,
		Location:    m.Location,
		CheckedAt:   time.Now().UTC(),
	}

	host := m.URL
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "tcp://")
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}

	port := m.TCPPort
	if port == 0 {
		if idx := strings.LastIndex(host, ":"); idx != -1 {
			portStr := host[idx+1:]
			host = host[:idx]
			fmt.Sscanf(portStr, "%d", &port)
		}
	}

	if port == 0 {
		result.Success = false
		result.ErrorMessage = "TCP port not specified"
		return result
	}

	address := fmt.Sprintf("%s:%d", host, port)

	timeout := time.Duration(m.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	dialer := net.Dialer{Timeout: timeout}

	start := time.Now()
	conn, err := dialer.Dial("tcp", address)
	elapsed := time.Since(start)
	result.ResponseTimeMs = elapsed.Milliseconds()

	if err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("TCP connection failed: %v", err)
		return result
	}
	defer conn.Close()

	result.Success = true
	result.StatusCode = 200
	result.ResponseBody = fmt.Sprintf("Successfully connected to %s", address)
	return result
}
