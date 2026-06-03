package scanner

import (
	"context"
	"github.com/temren/internal/payloads"
	"github.com/temren/pkg/httpengine"
	"net/url"
	"strings"
	"time"
)

// SSRFScanner detects Server-Side Request Forgery
type SSRFScanner struct{}

func NewSSRFScanner() *SSRFScanner {
	return &SSRFScanner{}
}

func (s *SSRFScanner) Name() string {
	return "Server-Side Request Forgery (SSRF)"
}

// Scan tests for SSRF
func (s *SSRFScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	query := u.Query()
	if len(query) == 0 {
		return findings, nil
	}

	for param, vals := range query {
		_ = vals
		for _, payload := range payloads.SSRF {
			testQuery := url.Values{}
			for k, v := range query {
				if k == param {
					testQuery.Set(k, payload)
				} else {
					testQuery.Set(k, v[0])
				}
			}

			testURL := u.Scheme + "://" + u.Host + u.Path + "?" + testQuery.Encode()

			resp, err := client.Get(ctx, testURL)
			if err != nil {
				continue
			}

			body, _ := readBody(resp)
			resp.Body.Close()

			if s.detectSSRFResponse(string(body), payload) {
				findings = append(findings, Finding{
					URL:         testURL,
					Title:       "Server-Side Request Forgery",
					Description: "SSRF vulnerability detected in parameter: " + param,
					Severity:    SeverityHigh,
					Confidence:  ConfidenceHigh,
					Payload:     payload,
					Evidence:    "Response indicates internal resource access",
					Scanner:     s.Name(),
					Timestamp:   time.Now(),
				})
				break
			}
		}
	}

	return findings, nil
}

// detectSSRFResponse checks for SSRF indicators
func (s *SSRFScanner) detectSSRFResponse(body, payload string) bool {
	// Check for file content indicators
	indicators := []string{
		"root:",
		"/bin/bash",
		"[fonts]",
		"[extensions]",
		"ami-id",
		"instance-id",
		"local-hostname",
		"local-ipv4",
		"computeMetadata",
		"metadata.google",
	}

	for _, ind := range indicators {
		if strings.Contains(body, ind) {
			return true
		}
	}

	// If payload is file:// and we got content
	if strings.HasPrefix(payload, "file://") && len(body) > 0 {
		return true
	}

	return false
}

