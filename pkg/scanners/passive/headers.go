// Package passive provides passive security scanners.
//
// Deprecated: use github.com/temren/pkg/scanner (SecurityHeadersScanner,
// HSTSPreloadScanner, ClickjackingScanner, CSPBypassScanner, ServerFingerprint
// Scanner) instead. Will be removed in v2.0.
package passive

import (
	"net/http"
	"regexp"
	"strings"
	"time"
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

// Finding represents a passive security finding
type Finding struct {
	URL         string
	Title       string
	Description string
	Severity    Severity
	Evidence    string
	Remediation string
	Scanner     string
	Timestamp   time.Time
}

// Scanner interface for passive scanners
type Scanner interface {
	Name() string
	Scan(resp *http.Response, url string) []Finding
}

// HeaderScanner analyzes HTTP headers for security issues
type HeaderScanner struct{}

// NewHeaderScanner creates a new header scanner
func NewHeaderScanner() *HeaderScanner {
	return &HeaderScanner{}
}

// Name returns the scanner name
func (s *HeaderScanner) Name() string {
	return "Header Security Analyzer"
}

// Scan analyzes response headers for security issues
func (s *HeaderScanner) Scan(resp *http.Response, url string) []Finding {
	var findings []Finding
	headers := resp.Header

	// Check for missing security headers
	findings = append(findings, s.checkMissingSecurityHeaders(headers, url)...)

	// Check for insecure header values
	findings = append(findings, s.checkInsecureHeaders(headers, url)...)

	// Check for information disclosure
	findings = append(findings, s.checkInformationDisclosure(headers, url)...)

	// Check for cookie security
	findings = append(findings, s.checkCookieSecurity(resp, url)...)

	return findings
}

// checkMissingSecurityHeaders checks for missing important security headers
func (s *HeaderScanner) checkMissingSecurityHeaders(headers http.Header, url string) []Finding {
	var findings []Finding

	securityHeaders := []struct {
		name        string
		severity    Severity
		description string
		remediation string
	}{
		{
			name:        "X-Frame-Options",
			severity:    SeverityMedium,
			description: "Missing X-Frame-Options header - page may be vulnerable to clickjacking",
			remediation: "Add: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN",
		},
		{
			name:        "X-Content-Type-Options",
			severity:    SeverityLow,
			description: "Missing X-Content-Type-Options header - browser may MIME-sniff content",
			remediation: "Add: X-Content-Type-Options: nosniff",
		},
		{
			name:        "Strict-Transport-Security",
			severity:    SeverityHigh,
			description: "Missing Strict-Transport-Security header - connection may be vulnerable to downgrade attacks",
			remediation: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
		},
		{
			name:        "Content-Security-Policy",
			severity:    SeverityHigh,
			description: "Missing Content-Security-Policy header - increased XSS risk",
			remediation: "Add a Content-Security-Policy header with appropriate directives",
		},
		{
			name:        "X-XSS-Protection",
			severity:    SeverityLow,
			description: "Missing X-XSS-Protection header - browser XSS filter may not be enabled",
			remediation: "Add: X-XSS-Protection: 1; mode=block",
		},
		{
			name:        "Referrer-Policy",
			severity:    SeverityLow,
			description: "Missing Referrer-Policy header - full URL may be leaked in Referer header",
			remediation: "Add: Referrer-Policy: strict-origin-when-cross-origin",
		},
		{
			name:        "Permissions-Policy",
			severity:    SeverityInfo,
			description: "Missing Permissions-Policy header - browser features not restricted",
			remediation: "Add Permissions-Policy header to restrict browser features",
		},
	}

	for _, h := range securityHeaders {
		if headers.Get(h.name) == "" {
			findings = append(findings, Finding{
				URL:         url,
				Title:       "Missing " + h.name + " Header",
				Description: h.description,
				Severity:    h.severity,
				Evidence:    "Header not present in response",
				Remediation: h.remediation,
				Scanner:     s.Name(),
				Timestamp:   time.Now(),
			})
		}
	}

	return findings
}

// checkInsecureHeaders checks for insecure header configurations
func (s *HeaderScanner) checkInsecureHeaders(headers http.Header, url string) []Finding {
	var findings []Finding

	// Check X-Frame-Options
	xfo := headers.Get("X-Frame-Options")
	if xfo != "" {
		upperXFO := strings.ToUpper(xfo)
		if !strings.Contains(upperXFO, "DENY") && !strings.Contains(upperXFO, "SAMEORIGIN") {
			findings = append(findings, Finding{
				URL:         url,
				Title:       "Weak X-Frame-Options Configuration",
				Description: "X-Frame-Options header has a weak or invalid value",
				Severity:    SeverityLow,
				Evidence:    "X-Frame-Options: " + xfo,
				Remediation: "Use DENY or SAMEORIGIN",
				Scanner:     s.Name(),
				Timestamp:   time.Now(),
			})
		}
	}

	// Check X-XSS-Protection
	xssProt := headers.Get("X-XSS-Protection")
	if xssProt != "" && !strings.HasPrefix(xssProt, "1") {
		findings = append(findings, Finding{
			URL:         url,
			Title:       "XSS Protection Disabled",
			Description: "X-XSS-Protection header has protection disabled",
			Severity:    SeverityMedium,
			Evidence:    "X-XSS-Protection: " + xssProt,
			Remediation: "Use: X-XSS-Protection: 1; mode=block",
			Scanner:     s.Name(),
			Timestamp:   time.Now(),
		})
	}

	// Check HSTS
	hsts := headers.Get("Strict-Transport-Security")
	if hsts != "" {
		if !strings.Contains(hsts, "max-age") {
			findings = append(findings, Finding{
				URL:         url,
				Title:       "Invalid HSTS Header",
				Description: "HSTS header missing max-age directive",
				Severity:    SeverityMedium,
				Evidence:    "Strict-Transport-Security: " + hsts,
				Remediation: "Add max-age directive: max-age=31536000",
				Scanner:     s.Name(),
				Timestamp:   time.Now(),
			})
		}
	}

	// Check Access-Control-Allow-Origin
	cors := headers.Get("Access-Control-Allow-Origin")
	if cors == "*" {
		findings = append(findings, Finding{
			URL:         url,
			Title:       "Overly Permissive CORS",
			Description: "Access-Control-Allow-Origin is set to wildcard",
			Severity:    SeverityMedium,
			Evidence:    "Access-Control-Allow-Origin: *",
			Remediation: "Restrict to specific origins instead of using wildcard",
			Scanner:     s.Name(),
			Timestamp:   time.Now(),
		})
	}

	// Check for credentials with wildcard CORS
	cred := headers.Get("Access-Control-Allow-Credentials")
	if cred == "true" && cors == "*" {
		findings = append(findings, Finding{
			URL:         url,
			Title:       "Critical CORS Misconfiguration",
			Description: "CORS allows credentials with wildcard origin - severe security risk",
			Severity:    SeverityCritical,
			Evidence:    "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
			Remediation: "Never use wildcard with credentials; specify exact origins",
			Scanner:     s.Name(),
			Timestamp:   time.Now(),
		})
	}

	return findings
}

// checkInformationDisclosure checks for headers that leak information
func (s *HeaderScanner) checkInformationDisclosure(headers http.Header, url string) []Finding {
	var findings []Finding

	// Server header
	server := headers.Get("Server")
	if server != "" {
		// Check for version disclosure
		versionPattern := regexp.MustCompile(`[\d]+\.[\d]+|[\d]+`)
		if versionPattern.MatchString(server) {
			findings = append(findings, Finding{
				URL:         url,
				Title:       "Server Version Disclosure",
				Description: "Server header reveals version information",
				Severity:    SeverityLow,
				Evidence:    "Server: " + server,
				Remediation: "Configure server to hide version information",
				Scanner:     s.Name(),
				Timestamp:   time.Now(),
			})
		}
	}

	// X-Powered-By header
	xpb := headers.Get("X-Powered-By")
	if xpb != "" {
		findings = append(findings, Finding{
			URL:         url,
			Title:       "Technology Disclosure via X-Powered-By",
			Description: "X-Powered-By header reveals technology stack",
			Severity:    SeverityInfo,
			Evidence:    "X-Powered-By: " + xpb,
			Remediation: "Remove X-Powered-By header from responses",
			Scanner:     s.Name(),
			Timestamp:   time.Now(),
		})
	}

	// X-AspNet-Version header
	aspnet := headers.Get("X-AspNet-Version")
	if aspnet != "" {
		findings = append(findings, Finding{
			URL:         url,
			Title:       "ASP.NET Version Disclosure",
			Description: "X-AspNet-Version header reveals framework version",
			Severity:    SeverityLow,
			Evidence:    "X-AspNet-Version: " + aspnet,
			Remediation: "Disable X-AspNet-Version header in web.config",
			Scanner:     s.Name(),
			Timestamp:   time.Now(),
		})
	}

	// X-Generator header
	gen := headers.Get("X-Generator")
	if gen != "" {
		findings = append(findings, Finding{
			URL:         url,
			Title:       "CMS Generator Disclosure",
			Description: "X-Generator header reveals CMS information",
			Severity:    SeverityInfo,
			Evidence:    "X-Generator: " + gen,
			Remediation: "Remove X-Generator header from responses",
			Scanner:     s.Name(),
			Timestamp:   time.Now(),
		})
	}

	return findings
}

// checkCookieSecurity analyzes cookie security attributes
func (s *HeaderScanner) checkCookieSecurity(resp *http.Response, url string) []Finding {
	var findings []Finding

	for _, cookie := range resp.Cookies() {
		var issues []string

		// Check Secure flag
		if !cookie.Secure {
			issues = append(issues, "missing Secure flag")
		}

		// Check HttpOnly flag
		if !cookie.HttpOnly {
			issues = append(issues, "missing HttpOnly flag")
		}

		// Check SameSite
		if cookie.SameSite == http.SameSiteDefaultMode {
			// SameSite not explicitly set
			issues = append(issues, "SameSite not set")
		}

		if len(issues) > 0 {
			severity := SeverityLow
			if !cookie.Secure && !cookie.HttpOnly {
				severity = SeverityMedium
			}

			findings = append(findings, Finding{
				URL:         url,
				Title:       "Insecure Cookie: " + cookie.Name,
				Description: "Cookie has security issues: " + strings.Join(issues, ", "),
				Severity:    severity,
				Evidence:    cookie.String(),
				Remediation: "Set Secure, HttpOnly, and SameSite=Strict/Lax attributes",
				Scanner:     s.Name(),
				Timestamp:   time.Now(),
			})
		}
	}

	return findings
}

// TLSScanner analyzes TLS-related security
type TLSScanner struct{}

// NewTLSScanner creates a new TLS scanner
func NewTLSScanner() *TLSScanner {
	return &TLSScanner{}
}

// Name returns scanner name
func (s *TLSScanner) Name() string {
	return "TLS Security Analyzer"
}

// Scan analyzes TLS configuration (placeholder for future implementation)
func (s *TLSScanner) Scan(resp *http.Response, url string) []Finding {
	var findings []Finding

	// Check if HTTPS is used
	if !strings.HasPrefix(url, "https://") {
		findings = append(findings, Finding{
			URL:         url,
			Title:       "Insecure HTTP Connection",
			Description: "Connection is not using HTTPS",
			Severity:    SeverityHigh,
			Evidence:    "URL scheme: http",
			Remediation: "Enforce HTTPS for all connections",
			Scanner:     s.Name(),
			Timestamp:   time.Now(),
		})
	}

	return findings
}
