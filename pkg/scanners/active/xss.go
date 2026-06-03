package active

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/temren/internal/payloads"
	"github.com/temren/pkg/httpengine"
)

// XSSScanner detects Cross-Site Scripting vulnerabilities
type XSSScanner struct {
	Payloads []string
}

// NewXSSScanner creates a new XSS scanner
func NewXSSScanner() *XSSScanner {
	return &XSSScanner{
		Payloads: payloads.XSS,
	}
}

// Name returns the scanner name
func (s *XSSScanner) Name() string {
	return "Cross-Site Scripting (XSS)"
}

// Scan tests for XSS vulnerabilities
func (s *XSSScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
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
		for _, payload := range s.Payloads {
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

			if s.isPayloadReflected(payload, string(body)) {
				findings = append(findings, Finding{
					URL:         testURL,
					Title:       "Reflected XSS",
					Description: "Cross-Site Scripting vulnerability detected in parameter: " + param,
					Severity:    SeverityHigh,
					Payload:     payload,
					Evidence:    "Payload reflected in response without proper encoding",
					Scanner:     s.Name(),
					Timestamp:   time.Now(),
				})
				break
			}
		}
	}

	return findings, nil
}

// isPayloadReflected checks if XSS payload is reflected in response
func (s *XSSScanner) isPayloadReflected(payload, body string) bool {
	// Check for direct reflection
	if strings.Contains(body, payload) {
		return true
	}

	// Check for URL-decoded reflection
	decodedPayload := strings.ReplaceAll(payload, "&lt;", "<")
	decodedPayload = strings.ReplaceAll(decodedPayload, "&gt;", ">")
	decodedPayload = strings.ReplaceAll(decodedPayload, "&quot;", "\"")
	decodedPayload = strings.ReplaceAll(decodedPayload, "&#39;", "'")
	if strings.Contains(body, decodedPayload) {
		return true
	}

	// Check for common XSS patterns in response
	xssIndicators := []string{
		"<script>alert",
		"onerror=alert",
		"onload=alert",
		"onfocus=alert",
		"onmouseover=alert",
		"onclick=alert",
		"javascript:alert",
		"<img src=x onerror",
		"<svg onload",
		"<body onload",
		"<iframe src",
		"expression(",
		"vbscript:",
	}

	lowerBody := strings.ToLower(body)
	for _, indicator := range xssIndicators {
		if strings.Contains(lowerBody, strings.ToLower(indicator)) {
			return true
		}
	}

	return false
}

// DOMXSSScanner detects DOM-based XSS vulnerabilities
type DOMXSSScanner struct {
	Payloads []string
}

// NewDOMXSSScanner creates a DOM XSS scanner
func NewDOMXSSScanner() *DOMXSSScanner {
	return &DOMXSSScanner{
		Payloads: []string{
			"'><script>alert(1)</script>",
			"\"><script>alert(1)</script>",
			"javascript:alert(1)",
			"data:text/html,<script>alert(1)</script>",
			"#'><script>alert(1)</script>",
			"?param=<script>alert(1)</script>",
			"'><img src=x onerror=alert(1)>",
			"\"><img src=x onerror=alert(1)>",
		},
	}
}

// Name returns scanner name
func (s *DOMXSSScanner) Name() string {
	return "DOM-Based XSS"
}

// Scan tests for DOM-based XSS
func (s *DOMXSSScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	// Test with fragment-based payloads
	for _, payload := range s.Payloads {
		testURL := target + payload

		resp, err := client.Get(ctx, testURL)
		if err != nil {
			continue
		}

		body, _ := readBody(resp)
		resp.Body.Close()

		// Check for dangerous sinks
		if s.hasDOMXSSSink(string(body)) {
			findings = append(findings, Finding{
				URL:         testURL,
				Title:       "Potential DOM-Based XSS",
				Description: "DOM-based XSS sink detected, payload in fragment may be executed",
				Severity:    SeverityMedium,
				Payload:     payload,
				Evidence:    "Dangerous DOM sink found in page source",
				Scanner:     s.Name(),
				Timestamp:   time.Now(),
			})
		}
	}

	return findings, nil
}

// hasDOMXSSSink checks for dangerous DOM sinks
func (s *DOMXSSScanner) hasDOMXSSSink(body string) bool {
	sinks := []string{
		"document.write(",
		"document.writeln(",
		"innerHTML",
		"outerHTML",
		"eval(",
		"setTimeout(",
		"setInterval(",
		"location.href",
		"location.hash",
		"location.search",
		"document.URL",
		"document.documentURI",
		"document.baseURI",
		"document.referrer",
		"window.name",
		".src =",
		".href =",
		"jQuery(",
		"$(",
		"angular.element(",
		"document.cookie",
	}

	lowerBody := strings.ToLower(body)
	for _, sink := range sinks {
		if strings.Contains(lowerBody, strings.ToLower(sink)) {
			return true
		}
	}
	return false
}

// StoredXSSScanner checks for stored XSS (requires form analysis)
type StoredXSSScanner struct {
	Payloads []string
}

// NewStoredXSSScanner creates a stored XSS scanner
func NewStoredXSSScanner() *StoredXSSScanner {
	return &StoredXSSScanner{
		Payloads: []string{
			"<script>alert('XSS')</script>",
			"<img src=x onerror=alert(1)>",
			"<svg/onload=alert(1)>",
			"'\"><script>alert(1)</script>",
			"javascript:alert(1)",
		},
	}
}

// Name returns scanner name
func (s *StoredXSSScanner) Name() string {
	return "Stored XSS"
}

// ScanForm submits a form with XSS payloads
func (s *StoredXSSScanner) ScanForm(ctx context.Context, formURL, formAction string, fields map[string]string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	for field := range fields {
		for _, payload := range s.Payloads {
			formData := url.Values{}
			for k, v := range fields {
				if k == field {
					formData.Set(k, payload)
				} else {
					formData.Set(k, v)
				}
			}

			resp, err := client.Post(ctx, formAction, "application/x-www-form-urlencoded", strings.NewReader(formData.Encode()))
			if err != nil {
				continue
			}

			body, _ := readBody(resp)
			resp.Body.Close()

			if strings.Contains(string(body), payload) {
				findings = append(findings, Finding{
					URL:         formAction,
					Title:       "Potential Stored XSS",
					Description: "XSS payload reflected after form submission in field: " + field,
					Severity:    SeverityHigh,
					Payload:     payload,
					Evidence:    "Payload stored and reflected in response",
					Scanner:     s.Name(),
					Timestamp:   time.Now(),
				})
				break
			}
		}
	}

	return findings, nil
}
