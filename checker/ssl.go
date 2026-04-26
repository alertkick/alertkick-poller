package checker

import (
	"alertkick-poller/client"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

func performSSLCheck(m *client.MonitorAssignment) *Result {
	result := &Result{
		MonitorUUID: m.UUID,
		Subdomain:   m.Subdomain,
		Location:    m.Location,
		CheckedAt:   time.Now().UTC(),
	}

	parsedURL, err := url.Parse(m.URL)
	if err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("failed to parse URL: %v", err)
		return result
	}

	if parsedURL.Scheme != "https" {
		result.Success = false
		result.ErrorMessage = "URL is not HTTPS"
		return result
	}

	host := parsedURL.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	timeout := time.Duration(m.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", host, &tls.Config{
		InsecureSkipVerify: false,
	})
	if err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("TLS connection failed: %v", err)
		return result
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		result.Success = false
		result.ErrorMessage = "no certificates found"
		return result
	}

	cert := certs[0]
	now := time.Now().UTC()
	daysRemaining := int(cert.NotAfter.Sub(now).Hours() / 24)

	result.Success = true
	result.StatusCode = 200
	result.ResponseBody = fmt.Sprintf("SSL cert expires in %d days (on %s), issuer: %s",
		daysRemaining, cert.NotAfter.Format("2006-01-02"), cert.Issuer.String())

	// Check if cert is expiring soon
	alertDays := 30
	if m.SSLCertExpiryAlertDays != nil {
		alertDays = *m.SSLCertExpiryAlertDays
	}
	if daysRemaining <= alertDays {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("SSL certificate expires in %d days (threshold: %d days)",
			daysRemaining, alertDays)
	}

	return result
}
