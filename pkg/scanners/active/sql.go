package active

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/temren/internal/payloads"
	"github.com/temren/pkg/httpengine"
)

// SQLiScanner detects SQL injection vulnerabilities
type SQLiScanner struct {
	Payloads []string
}

// NewSQLiScanner creates a new SQL injection scanner
func NewSQLiScanner() *SQLiScanner {
	return &SQLiScanner{
		Payloads: payloads.SQLInjection,
	}
}

// Name returns the scanner name
func (s *SQLiScanner) Name() string {
	return "SQL Injection"
}

// Scan tests for SQL injection vulnerabilities
func (s *SQLiScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
	var findings []Finding

	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	query := u.Query()
	if len(query) == 0 {
		return findings, nil
	}

	for param, values := range query {
		originalValue := values[0]

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

			if s.detectSQLError(string(body)) {
				findings = append(findings, Finding{
					URL:         testURL,
					Title:       "SQL Injection",
					Description: "SQL injection vulnerability detected in parameter: " + param,
					Severity:    SeverityCritical,
					Payload:     payload,
					Evidence:    "SQL error message detected in response",
					Scanner:     s.Name(),
					Timestamp:   time.Now(),
				})
				break
			}
		}

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
		"mysql_affected_rows()",
		"ORA-",
		"PLS-",
		"incorrect syntax near",
		"Warning: mysql_",
		"PostgreSQL query failed",
		"supplied argument is not a valid MySQL",
		"java.sql.SQLException",
		"org.sqlite.SQLiteException",
		"System.Data.OleDb.OleDbException",
		"Unclosed quotation mark after character string",
	}

	lowerBody := strings.ToLower(body)
	for _, err := range sqlErrors {
		if strings.Contains(lowerBody, strings.ToLower(err)) {
			return true
		}
	}
	return false
}

// TimeBasedSQLiScanner detects time-based SQL injection
type TimeBasedSQLiScanner struct {
	Payloads   []string
	Threshold  time.Duration
}

// NewTimeBasedSQLiScanner creates a time-based SQLi scanner
func NewTimeBasedSQLiScanner() *TimeBasedSQLiScanner {
	return &TimeBasedSQLiScanner{
		Payloads: []string{
			"' AND SLEEP(5)--",
			"' AND BENCHMARK(5000000,SHA1('test'))--",
			"'; WAITFOR DELAY '0:0:5'--",
			"1; SELECT SLEEP(5)--",
			"' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
			"1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
		},
		Threshold: 4 * time.Second,
	}
}

// Name returns scanner name
func (s *TimeBasedSQLiScanner) Name() string {
	return "Time-Based SQL Injection"
}

// Scan tests for time-based SQL injection
func (s *TimeBasedSQLiScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
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
		_ = vals // original values preserved for iteration
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

			start := time.Now()
			resp, err := client.Get(ctx, testURL)
			elapsed := time.Since(start)

			if err != nil {
				continue
			}
			resp.Body.Close()

			if elapsed >= s.Threshold {
				findings = append(findings, Finding{
					URL:         testURL,
					Title:       "Time-Based SQL Injection",
					Description: "Time-based SQL injection detected in parameter: " + param,
					Severity:    SeverityHigh,
					Payload:     payload,
					Evidence:    "Response delayed by " + elapsed.String(),
					Scanner:     s.Name(),
					Timestamp:   time.Now(),
				})
				break
			}
		}
	}

	return findings, nil
}
