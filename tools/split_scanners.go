// +build ignore

package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

type Scanner struct {
	Name  string
	Start int
	End   int
	File  string
}

func main() {
	scanners := []Scanner{
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

	// Read scanner.go
	content, err := os.ReadFile("pkg/scanner/scanner.go")
	if err != nil {
		panic(err)
	}
	lines := strings.Split(string(content), "\n")

	for _, s := range scanners {
		extractScanner(lines, s)
	}

	// Now trim scanner.go - keep only package through Scanner interface (line 50)
	// plus lines 159-172 (readBody helper)
	fmt.Println("Scanner split complete. Manually trim scanner.go to keep only:")
	fmt.Println("1. Lines 1-50 (package, imports, Severity, Finding, Scanner interface)")
	fmt.Println("2. Lines 159-172 (readBody helper)")
}

func extractScanner(lines []string, s Scanner) {
	var sb strings.Builder
	sb.WriteString("package scanner\n\n")

	// Collect imports
	imports := collectImports(lines, s.Start, s.End)
	if len(imports) > 0 {
		sb.WriteString("import (\n")
		for _, imp := range imports {
			sb.WriteString(fmt.Sprintf("\t\"%s\"\n", imp))
		}
		sb.WriteString(")\n\n")
	}

	// Write scanner code
	skipBlank := true
	for i := s.Start - 1; i < s.End && i < len(lines); i++ {
		line := lines[i]
		// Skip leading blank lines
		if skipBlank && strings.TrimSpace(line) == "" {
			continue
		}
		skipBlank = false
		sb.WriteString(line + "\n")
	}

	path := "pkg/scanner/" + s.File
	err := os.WriteFile(path, []byte(sb.String()), 0644)
	if err != nil {
		fmt.Printf("Error writing %s: %v\n", s.File, err)
	} else {
		fmt.Printf("Created %s (%d-%d)\n", s.File, s.Start, s.End)
	}
}

func collectImports(lines []string, start, end int) []string {
	importSet := make(map[string]bool)
	re := regexp.MustCompile(`"([^"]+)"`)

	for i := start - 1; i < end && i < len(lines); i++ {
		matches := re.FindAllStringSubmatch(lines[i], -1)
		for _, m := range matches {
			pkg := m[1]
			// Skip standard library packages that are already in scope
			if strings.Contains(lines[i], "readBody") || strings.Contains(lines[i], "resp.Body") {
				importSet["io"] = true
			}
			// External packages
			if strings.HasPrefix(pkg, "github.com/temren/") {
				importSet[pkg] = true
			}
		}
		// Check for standard library usage
		if strings.Contains(lines[i], "context.") && !strings.Contains(lines[i], "\"context\"") {
			importSet["context"] = true
		}
		if strings.Contains(lines[i], "strings.") {
			importSet["strings"] = true
		}
		if strings.Contains(lines[i], "strconv.") {
			importSet["strconv"] = true
		}
		if strings.Contains(lines[i], "regexp.") {
			importSet["regexp"] = true
		}
		if strings.Contains(lines[i], "url.") || strings.Contains(lines[i], "net/url") {
			importSet["net/url"] = true
		}
		if strings.Contains(lines[i], "http.") || strings.Contains(lines[i], "net/http") {
			importSet["net/http"] = true
		}
		if strings.Contains(lines[i], "fmt.") {
			importSet["fmt"] = true
		}
		if strings.Contains(lines[i], "time.") {
			importSet["time"] = true
		}
		if strings.Contains(lines[i], "sync.") {
			importSet["sync"] = true
		}
		if strings.Contains(lines[i], "json.") || strings.Contains(lines[i], "encoding/json") {
			importSet["encoding/json"] = true
		}
		if strings.Contains(lines[i], "tls.") || strings.Contains(lines[i], "crypto/tls") {
			importSet["crypto/tls"] = true
		}
		if strings.Contains(lines[i], "io.") || strings.Contains(lines[i], "ioutil") {
			importSet["io"] = true
		}
	}

	var result []string
	for imp := range importSet {
		result = append(result, imp)
	}
	return result
}
