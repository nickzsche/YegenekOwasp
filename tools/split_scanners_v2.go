//go:build ignore

package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// Scanner definition: name, start line, end line, output filename
type ScannerDef struct {
	Name  string
	Start int
	End   int
	File  string
}

func main() {
	scanners := []ScannerDef{
		{"SQLiScanner", 52, 173, "sqli.go"},
		{"XSSScanner", 174, 266, "xss_scanner.go"},
		{"CommandInjectionScanner", 267, 357, "command_injection.go"},
		{"SSRFScanner", 358, 453, "ssrf.go"},
		{"XXEScanner", 454, 518, "xxe_scanner.go"},
		{"PathTraversalScanner", 519, 601, "path_traversal.go"},
		{"IDORScanner", 602, 677, "idor.go"},
		{"AuthFailureScanner", 678, 753, "auth_failure.go"},
		{"VulnerableComponentsScanner", 754, 823, "vulnerable_components.go"},
		{"LoggingMonitoringScanner", 824, 905, "logging_monitoring.go"},
		{"InsecureDesignScanner", 906, 982, "insecure_design.go"},
		{"ErrorHandlingScanner", 983, 1089, "error_handling.go"},
		{"SoftwareSupplyChainScanner", 1090, 1167, "software_supply_chain.go"},
		{"FormParameterScanner", 1168, 1283, "form_parameter.go"},
		{"WAFDetector", 1284, 1376, "waf_detector.go"},
		{"SubdomainEnumerator", 1377, 1427, "subdomain.go"},
		{"BackupFileScanner", 1428, 1515, "backup_file.go"},
		{"DirectoryBruteForceScanner", 1516, 1595, "directory_bruteforce.go"},
		{"TechnologyDetector", 1596, 1692, "technology_detector.go"},
		{"JWTScanner", 1693, 1756, "jwt_scanner.go"},
		{"GraphQLScanner", 1757, 1826, "graphql.go"},
		{"OpenRedirectScanner", 1827, 1898, "open_redirect.go"},
		{"HoneypotDetector", 1899, 1978, "honeypot.go"},
		{"SwaggerScanner", 1979, 2069, "swagger.go"},
		{"ParameterMiner", 2070, 2151, "parameter_miner.go"},
		{"PrototypePollutionScanner", 2152, 2224, "prototype_pollution.go"},
		{"CloudLeakScanner", 2225, 2392, "cloud_leak.go"},
	}

	content, err := os.ReadFile("pkg/scanner/scanner.go")
	if err != nil {
		panic(err)
	}
	lines := strings.Split(string(content), "\n")

	for _, s := range scanners {
		code := extractCode(lines, s.Start, s.End)
		imports := detectImports(code)
		writeScannerFile(s.File, code, imports)
		fmt.Printf("  %s (%d lines)\n", s.File, s.End-s.Start+1)
	}

	fmt.Println("\nDone. Now trim scanner.go manually.")
}

func extractCode(lines []string, start, end int) string {
	var sb strings.Builder
	for i := start - 1; i < end && i < len(lines); i++ {
		sb.WriteString(lines[i])
		sb.WriteByte('\n')
	}
	return sb.String()
}

func detectImports(code string) []string {
	importSet := make(map[string]string)

	// Standard library checks
	checks := map[string]string{
		"context":       "context.",
		"fmt":           "fmt.",
		"net/http":      "http.",
		"net/url":       "url.",
		"regexp":        "regexp.",
		"strconv":       "strconv.",
		"strings":       "strings.",
		"sync":          "sync.",
		"time":          "time.",
		"crypto/tls":    "tls.",
		"encoding/json": "json.",
		"io":            "io.",
		"bufio":         "bufio.",
		"math/rand":     "rand.",
	}

	for pkg, token := range checks {
		if strings.Contains(code, token) {
			importSet[pkg] = pkg
		}
	}

	// Also check for specific patterns
	if strings.Contains(code, "resp.Body") || strings.Contains(code, "*http.Response") || strings.Contains(code, "http.Status") || strings.Contains(code, "http.Cookie") || strings.Contains(code, "httptest") {
		importSet["net/http"] = "net/http"
	}

	// External packages
	externals := map[string]string{
		"github.com/temren/internal/payloads": "payloads.",
		"github.com/temren/pkg/httpengine":    "httpengine.",
		"github.com/temren/pkg/spider":        "spider.",
		"github.com/temren/pkg/wafbypass":     "wafbypass.",
	}

	for pkg, token := range externals {
		if strings.Contains(code, token) {
			importSet[pkg] = pkg
		}
	}

	// Sort imports
	var result []string
	for _, imp := range importSet {
		result = append(result, imp)
	}
	sort.Strings(result)
	return result
}

func writeScannerFile(filename, code string, imports []string) {
	var sb strings.Builder
	sb.WriteString("package scanner\n\n")

	if len(imports) > 0 {
		sb.WriteString("import (\n")
		for _, imp := range imports {
			sb.WriteString(fmt.Sprintf("\t\"%s\"\n", imp))
		}
		sb.WriteString(")\n\n")
	}

	// Clean the code: remove leading blank lines
	code = strings.TrimLeft(code, "\n")
	sb.WriteString(code)

	path := "pkg/scanner/" + filename
	os.WriteFile(path, []byte(sb.String()), 0644)
}
