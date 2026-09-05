package checker

import (
	"alertkick-poller/client"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"
)

func performHTTPCheck(m *client.MonitorAssignment, tlsInsecure bool) *Result {
	result := &Result{
		MonitorUUID: m.UUID,
		Subdomain:   m.Subdomain,
		Location:    m.Location,
		CheckedAt:   time.Now().UTC(),
	}

	timeout := time.Duration(m.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: tlsInsecure,
		},
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: timeout,
	}

	httpClient := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	var bodyReader io.Reader
	if m.RequestBody != nil && *m.RequestBody != "" {
		bodyReader = strings.NewReader(*m.RequestBody)
	}

	method := m.HTTPMethod
	if method == "" {
		method = "GET"
	}

	req, err := http.NewRequest(method, m.URL, bodyReader)
	if err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("failed to create request: %v", err)
		return result
	}

	// Headers
	for key, value := range m.Headers {
		req.Header.Set(key, value)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "AlertKick-Poller/1.0")
	}

	// Authentication
	if m.Auth != nil {
		switch m.Auth.Type {
		case "basic":
			auth := base64.StdEncoding.EncodeToString(
				[]byte(m.Auth.Username + ":" + m.Auth.Password),
			)
			req.Header.Set("Authorization", "Basic "+auth)
		case "bearer":
			req.Header.Set("Authorization", "Bearer "+m.Auth.Token)
		}
	}

	// Phase timings (DNS, connect, TLS, first byte) via httptrace; the
	// total is anchored after the body read so it reflects full load time.
	timings := newHTTPTimings()
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), timings.trace()))

	start := time.Now()
	resp, err := httpClient.Do(req)
	elapsed := time.Since(start)
	result.ResponseTimeMs = elapsed.Milliseconds()

	if err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("request failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err == nil {
		result.ResponseBody = string(bodyBytes)
	}
	result.Details = timings.details(time.Since(start))

	expectedStatus := m.ExpectedStatusCode
	if expectedStatus == 0 {
		expectedStatus = 200
	}

	if resp.StatusCode != expectedStatus {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("unexpected status code: got %d, expected %d", resp.StatusCode, expectedStatus)
		return result
	}

	if m.ExpectedResponseContains != nil && *m.ExpectedResponseContains != "" {
		if !strings.Contains(result.ResponseBody, *m.ExpectedResponseContains) {
			result.Success = false
			result.ErrorMessage = fmt.Sprintf("response does not contain expected string: %s", *m.ExpectedResponseContains)
			return result
		}
	}

	result.Success = true
	return result
}
