package scanner

import (
	"context"
	"github.com/temren/internal/payloads"
	"github.com/temren/pkg/httpengine"
	"net/url"
	"strings"
	"time"
)

// CommandInjectionScanner detects OS command injection
type CommandInjectionScanner struct{}

func NewCommandInjectionScanner() *CommandInjectionScanner {
	return &CommandInjectionScanner{}
}

func (s *CommandInjectionScanner) Name() string {
	return "Command Injection"
}

// Scan tests for command injection
func (s *CommandInjectionScanner) Scan(ctx context.Context, target string, client *httpengine.Client) ([]Finding, error) {
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
		for _, payload := range payloads.CommandInjection {
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

			if s.detectCommandOutput(string(body)) {
				findings = append(findings, Finding{
					URL:         testURL,
					Title:       "OS Command Injection",
					Description: "Command injection vulnerability detected in parameter: " + param,
					Severity:    SeverityCritical,
					Confidence:  ConfidenceHigh,
					Payload:     payload,
					Evidence:    "Command output detected in response",
					Scanner:     s.Name(),
					Timestamp:   time.Now(),
				})
				break
			}
		}
	}

	return findings, nil
}

// detectCommandOutput checks for command execution indicators
func (s *CommandInjectionScanner) detectCommandOutput(body string) bool {
	indicators := []string{
		"root:",
		"bin/bash",
		"total ",
		"drwx",
		"-rwx",
		"uid=",
		"gid=",
		"groups=",
		"[extensions]",
		"[fonts]",
		"Volume Serial Number",
		"Directory of",
	}

	for _, ind := range indicators {
		if strings.Contains(body, ind) {
			return true
		}
	}
	return false
}

