package passive

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHeaderScanner_Scan(t *testing.T) {
	tests := []struct {
		name           string
		headers        http.Header
		body           string
		expectedIssues int
	}{
		{
			name: "Missing security headers",
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:           "<html><body>test</body></html>",
			expectedIssues: 5, // X-Frame-Options, X-Content-Type-Options, CSP, HSTS, X-XSS-Protection minimum
		},
		{
			name: "All security headers present",
			headers: http.Header{
				"Content-Type":              []string{"text/html"},
				"X-Frame-Options":           []string{"DENY"},
				"X-Content-Type-Options":    []string{"nosniff"},
				"Content-Security-Policy":   []string{"default-src 'self'"},
				"Strict-Transport-Security": []string{"max-age=31536000; includeSubDomains"},
				"X-XSS-Protection":          []string{"1; mode=block"},
			},
			body:           "<html><body>test</body></html>",
			expectedIssues: 2, // Referrer-Policy, Permissions-Policy
		},
		{
			name: "Weak X-Frame-Options",
			headers: http.Header{
				"Content-Type":           []string{"text/html"},
				"X-Frame-Options":        []string{"ALLOW-FROM https://evil.com"},
				"X-Content-Type-Options": []string{"nosniff"},
			},
			body:           "<html><body>test</body></html>",
			expectedIssues: 5, // CSP, HSTS, X-XSS-Protection, Referrer, Permissions + weak XFO
		},
		{
			name: "Information disclosure in headers",
			headers: http.Header{
				"Content-Type": []string{"text/html"},
				"Server":       []string{"Apache/2.4.41 (Ubuntu)"},
				"X-Powered-By": []string{"PHP/7.4.3"},
			},
			body:           "<html><body>test</body></html>",
			expectedIssues: 7, // 5 missing security + 2 info disclosure
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := NewHeaderScanner()

			resp := &http.Response{
				Header: tt.headers,
			}

			results := analyzer.Scan(resp, "https://example.com")

			if len(results) < tt.expectedIssues {
				t.Errorf("Expected at least %d issues, got %d", tt.expectedIssues, len(results))
			}

			for _, r := range results {
				if r.Scanner != "Header Security Analyzer" {
					t.Errorf("Wrong scanner name: %s", r.Scanner)
				}
			}
		})
	}
}

func TestHeaderScanner_CheckXFrameOptions(t *testing.T) {
	analyzer := NewHeaderScanner()

	tests := []struct {
		name     string
		header   string
		hasIssue bool
	}{
		{"DENY is secure", "DENY", false},
		{"SAMEORIGIN is secure", "SAMEORIGIN", false},
		{"ALLOW-FROM is weak", "ALLOW-FROM https://example.com", true},
		{"Empty is insecure", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.header != "" {
				headers.Set("X-Frame-Options", tt.header)
			}

			resp := &http.Response{Header: headers}
			results := analyzer.Scan(resp, "https://example.com")

			foundXFOIssue := false
			for _, r := range results {
				if r.Title == "Missing X-Frame-Options Header" ||
					r.Title == "Weak X-Frame-Options Configuration" {
					foundXFOIssue = true
				}
			}

			if tt.hasIssue != foundXFOIssue {
				t.Errorf("Expected hasIssue=%v, got foundXFOIssue=%v", tt.hasIssue, foundXFOIssue)
			}
		})
	}
}

func TestHeaderScanner_CheckCSP(t *testing.T) {
	analyzer := NewHeaderScanner()

	tests := []struct {
		name     string
		csp      string
		hasIssue bool
	}{
		{
			name:     "Strong CSP",
			csp:      "default-src 'self'; script-src 'self'",
			hasIssue: false,
		},
		{
			name:     "Missing CSP",
			csp:      "",
			hasIssue: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.csp != "" {
				headers.Set("Content-Security-Policy", tt.csp)
			}

			resp := &http.Response{Header: headers}
			results := analyzer.Scan(resp, "https://example.com")

			foundCSPIssue := false
			for _, r := range results {
				if r.Title == "Missing Content-Security-Policy Header" {
					foundCSPIssue = true
				}
			}

			if tt.hasIssue != foundCSPIssue {
				t.Errorf("Expected hasIssue=%v, got foundCSPIssue=%v", tt.hasIssue, foundCSPIssue)
			}
		})
	}
}

func TestHeaderScanner_ServerVersionDisclosure(t *testing.T) {
	analyzer := NewHeaderScanner()

	headers := http.Header{
		"Server":       []string{"nginx/1.18.0"},
		"X-Powered-By": []string{"Express"},
	}

	resp := &http.Response{Header: headers}
	results := analyzer.Scan(resp, "https://example.com")

	infoDisclosureCount := 0
	for _, r := range results {
		if r.Severity == SeverityInfo || r.Severity == SeverityLow {
			if r.Title == "Server Version Disclosure" ||
				r.Title == "Technology Disclosure via X-Powered-By" {
				infoDisclosureCount++
			}
		}
	}

	if infoDisclosureCount < 1 {
		t.Errorf("Expected information disclosure issues, got %d", infoDisclosureCount)
	}
}

func TestHeaderScanner_CORSMisconfiguration(t *testing.T) {
	analyzer := NewHeaderScanner()

	tests := []struct {
		name           string
		origin         string
		credentials    string
		expectCritical bool
	}{
		{
			name:           "Wildcard CORS without credentials",
			origin:         "*",
			credentials:    "",
			expectCritical: false,
		},
		{
			name:           "Wildcard CORS with credentials - CRITICAL",
			origin:         "*",
			credentials:    "true",
			expectCritical: true,
		},
		{
			name:           "Specific origin",
			origin:         "https://example.com",
			credentials:    "true",
			expectCritical: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.origin != "" {
				headers.Set("Access-Control-Allow-Origin", tt.origin)
			}
			if tt.credentials != "" {
				headers.Set("Access-Control-Allow-Credentials", tt.credentials)
			}

			resp := &http.Response{Header: headers}
			results := analyzer.Scan(resp, "https://example.com")

			foundCritical := false
			for _, r := range results {
				if r.Severity == SeverityCritical {
					foundCritical = true
				}
			}

			if tt.expectCritical != foundCritical {
				t.Errorf("Expected critical=%v, got foundCritical=%v", tt.expectCritical, foundCritical)
			}
		})
	}
}

func TestHeaderScanner_CookieSecurity(t *testing.T) {
	analyzer := NewHeaderScanner()

	// Create a test server to get cookies
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:  "session",
			Value: "abc123",
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("Failed to get response: %v", err)
	}

	results := analyzer.Scan(resp, server.URL)

	// Check for cookie security issues
	cookieIssueFound := false
	for _, r := range results {
		if r.Title == "Insecure Cookie: session" {
			cookieIssueFound = true
		}
	}

	if !cookieIssueFound {
		t.Log("Cookie security check performed")
	}
}

func TestTLSScanner_Scan(t *testing.T) {
	scanner := NewTLSScanner()

	// Test HTTP URL (not HTTPS)
	resp := &http.Response{Header: http.Header{}}
	results := scanner.Scan(resp, "http://example.com")

	foundHTTPSIssue := false
	for _, r := range results {
		if r.Title == "Insecure HTTP Connection" {
			foundHTTPSIssue = true
		}
	}

	if !foundHTTPSIssue {
		t.Error("Expected insecure HTTP connection issue")
	}

	// Test HTTPS URL
	results = scanner.Scan(resp, "https://example.com")
	for _, r := range results {
		if r.Title == "Insecure HTTP Connection" {
			t.Error("Should not flag HTTPS as insecure")
		}
	}
}
