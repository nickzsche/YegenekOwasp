package scanner

import (
	"context"
	"github.com/temren/internal/payloads"
	"github.com/temren/pkg/httpengine"
	"net/url"
	"strings"
	"time"
)

// SQLiScanner detects SQL injection vulnerabilities
type SQLiScanner struct{}

func NewSQLiScanner() *SQLiScanner {
	return &SQLiScanner{}
}

func (s *SQLiScanner) Name() string {
	return "SQL Injection"
}

// Scan tests for SQL injection vulnerabilities
func (s *SQLiScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	// Parse URL to get parameters
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	query := u.Query()
	if len(query) == 0 {
		// No parameters to test
		return findings, nil
	}

	// Test each parameter
	for param, values := range query {
		originalValue := values[0]

		for _, payload := range payloads.SQLInjection {
			// Create new query with payload
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

			// Check for SQL error indicators
			if s.detectSQLError(string(body)) {
				findings = append(findings, Finding{
					URL:         testURL,
					Title:       "SQL Injection",
					Description: "SQL injection vulnerability detected in parameter: " + param,
					Severity:    SeverityCritical,
					Confidence:  ConfidenceHigh,
					Payload:     payload,
					Evidence:    "SQL error message detected in response",
					Scanner:     s.Name(),
					Timestamp:   time.Now(),
				})
				break // Found vulnerability, move to next parameter
			}
		}

		// Restore original value
		query.Set(param, originalValue)
	}

	return findings, nil
}

// detectSQLError checks for SQL error messages in response
func (s *SQLiScanner) detectSQLError(body string) bool {
	sqlErrors := []string{
		"SQL syntax",
		"mysql_fetch",
		"ORA-01756",
		"quoted string not properly terminated",
		"Unclosed quotation mark",
		"pg_query()",
		"Warning: pg_",
		"valid MySQL result",
		"MySqlClient.",
		"SQLSTATE[",
		"mysqli_",
		"Syntax error",
		"syntax error",
		"unexpected end of SQL command",
		"postgresql",
		"sqlite3.",
		"SQL error",
		"mysql_num_rows()",
		"mysql_fetch_array()",
	}

	for _, err := range sqlErrors {
		if strings.Contains(strings.ToLower(body), strings.ToLower(err)) {
			return true
		}
	}
	return false
}

// readBody reads response body as bytes

