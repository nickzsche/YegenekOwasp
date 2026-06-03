// Package active provides active vulnerability scanners.
//
// Deprecated: use github.com/temren/pkg/scanner instead. The unified
// pkg/scanner registry covers SQLi, XSS, and 78+ other scanners with a single
// Finding type and CVSS 4.0 scoring. This package is kept for backwards
// compatibility and will be removed in v2.0.
package active

import (
	"io"
	"net/http"
	"time"

	"github.com/temren/pkg/httpengine"
)

// Severity levels for findings
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Finding represents a security finding
type Finding struct {
	URL         string
	Title       string
	Description string
	Severity    Severity
	Payload     string
	Evidence    string
	Scanner     string
	Timestamp   time.Time
	Request     string
	Response    string
}

// Scanner interface for all active scanners
type Scanner interface {
	Name() string
	Scan(ctx interface{}, target string, client *httpengine.Client) ([]Finding, error)
}

// readBody reads response body safely
func readBody(resp *http.Response) ([]byte, error) {
	if resp.Body == nil {
		return nil, nil
	}
	defer resp.Body.Close()

	buf := make([]byte, 1024*1024) // 1MB max
	n, err := resp.Body.Read(buf)
	if err != nil && err.Error() != "EOF" {
		return nil, err
	}
	return buf[:n], nil
}

// ReadAllBody uses io.ReadAll for reading body
func ReadAllBody(resp *http.Response) ([]byte, error) {
	if resp.Body == nil {
		return nil, nil
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
