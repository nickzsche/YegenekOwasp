// Package scanner provides attack path analysis for chaining vulnerabilities
package scanner

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// AttackPath represents a chain of vulnerabilities that could be exploited together
type AttackPath struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	Description      string     `json:"description"`
	Steps            []PathStep `json:"steps"`
	OverallRisk      Severity   `json:"overall_risk"`
	OverallCVSS      float64    `json:"overall_cvss"`
	AttackComplexity string     `json:"attack_complexity"` // "low", "medium", "high"
}

// PathStep represents a single step in an attack path
type PathStep struct {
	Finding     Finding `json:"finding"`
	Role        string  `json:"role"`          // "entry_point", "privilege_escalation", "lateral_movement", "data_exfiltration", "impact"
	Description string  `json:"description"`   // How this finding is used in the chain
	EnablesNext string  `json:"enables_next"`  // What this step enables (reference to next finding's scanner name)
}

// ChainedFinding represents findings that are related by URL or parameter
type ChainedFinding struct {
	Finding   Finding          `json:"finding"`
	RelatedTo []ChainedFinding `json:"related_to,omitempty"`
}

// chainRule defines how one vulnerability type can lead to another
type chainRule struct {
	From        string // Scanner name of source finding
	To          string // Scanner name that can be reached
	Description string // How the chain works
}

// chainRules defines the rules for chaining findings into attack paths.
// These use the actual scanner Name() values from the project.
var chainRules = []chainRule{
	{"Cross-Site Scripting (XSS)", "Command Injection", "XSS can be used to execute commands in the context of an admin user"},
	{"Cross-Site Scripting (XSS)", "Insecure Direct Object Reference (IDOR)", "XSS steals session tokens → IDOR exploits authorization gaps"},
	{"Cross-Site Scripting (XSS)", "JWT Analysis", "XSS steals tokens → JWT manipulation for privilege escalation"},
	{"SQL Injection", "Path Traversal", "SQL injection can read files via LOAD_FILE() or pg_read_file()"},
	{"SQL Injection", "Command Injection", "SQL injection with xp_cmdshell or INTO OUTFILE → OS command execution"},
	{"Server-Side Request Forgery (SSRF)", "Cloud Leak Detection", "SSRF accesses cloud metadata endpoints → AWS/GCP credentials exposed"},
	{"Server-Side Request Forgery (SSRF)", "Path Traversal", "SSRF to internal services → path traversal on internal endpoints"},
	{"Server-Side Request Forgery (SSRF)", "GraphQL Security", "SSRF discovers internal GraphQL endpoints → schema introspection"},
	{"Authentication Failures", "Insecure Direct Object Reference (IDOR)", "Default credentials → authenticated IDOR exploitation"},
	{"Authentication Failures", "SQL Injection", "Default credentials → authenticated SQL injection with elevated privileges"},
	{"CORS Misconfiguration", "Insecure Direct Object Reference (IDOR)", "CORS allows cross-origin requests → IDOR on authenticated endpoints"},
	{"Open Redirect", "Authentication Failures", "Phishing via redirect → credential harvesting → unauthorized access"},
	{"Secret Scanner", "Command Injection", "Exposed credentials → server compromise via command injection"},
	{"JWT Analysis", "Insecure Direct Object Reference (IDOR)", "Forged JWT tokens → IDOR exploitation across user boundaries"},
	{"Path Traversal", "Command Injection", "Path traversal reads config files → command injection via config manipulation"},
	{"Insecure Direct Object Reference (IDOR)", "SQL Injection", "IDOR reveals database IDs → SQL injection on discovered parameters"},
	{"XML External Entity (XXE)", "Server-Side Request Forgery (SSRF)", "XXE makes internal requests → SSRF to internal services"},
	{"XML External Entity (XXE)", "Path Traversal", "XXE reads local files → path traversal for sensitive data access"},
	{"LLM/API Security Scanner", "Secret Scanner", "LLM prompt injection extracts system prompts → leaked API keys and secrets"},
	{"LLM/API Security Scanner", "Server-Side Request Forgery (SSRF)", "LLM tool use can be hijacked to make unauthorized internal requests"},
	{"LLM/API Security Scanner", "Command Injection", "LLM with tool access can be manipulated into executing shell commands"},
}

// entryPointScanners defines which scanner types are considered entry points
var entryPointScanners = map[string]string{
	"Cross-Site Scripting (XSS)":            "entry_point",
	"SQL Injection":                          "entry_point",
	"Server-Side Request Forgery (SSRF)":    "entry_point",
	"Authentication Failures":                "entry_point",
	"CORS Misconfiguration":                  "entry_point",
	"Open Redirect":                          "entry_point",
	"LLM/API Security Scanner":             "entry_point",
}

// roleMapping maps scanner names to their attack path roles when NOT the first step.
// Entry points are handled by getRole() which checks isFirstStep first.
var roleMapping = map[string]string{
	// Entry points (used when NOT the first step — first step is handled by getRole)
	"Cross-Site Scripting (XSS)":  "entry_point",
	"Authentication Failures":     "entry_point",
	"CORS Misconfiguration":      "entry_point",
	"Open Redirect":               "entry_point",
	// Privilege escalation
	"Insecure Direct Object Reference (IDOR)": "privilege_escalation",
	"Path Traversal":                           "privilege_escalation",
	"JWT Analysis":                              "privilege_escalation",
	"Command Injection":                         "privilege_escalation",
	// Lateral movement
	"Server-Side Request Forgery (SSRF)": "lateral_movement",
	"GraphQL Security":                   "lateral_movement",
	// Data exfiltration / impact
	"SQL Injection":        "data_exfiltration",
	"Secret Scanner":       "data_exfiltration",
	"Cloud Leak Detection": "data_exfiltration",
}

// getRole determines the primary role of a finding in an attack path.
// The role depends on context: if it's the first step, it's an entry point;
// otherwise, use the role mapping.
func getRole(scannerName string, isFirstStep bool) string {
	if isFirstStep {
		if _, ok := entryPointScanners[scannerName]; ok {
			return "entry_point"
		}
		return "entry_point" // any finding can be an entry point if it's first
	}
	if role, ok := roleMapping[scannerName]; ok {
		return role
	}
	return "impact"
}

// AttackPathAnalyzer analyzes findings and generates attack paths
type AttackPathAnalyzer struct {
	findings []Finding
}

// NewAttackPathAnalyzer creates a new analyzer from a set of findings
func NewAttackPathAnalyzer(findings []Finding) *AttackPathAnalyzer {
	return &AttackPathAnalyzer{findings: findings}
}

// Analyze generates attack paths from the findings
func (a *AttackPathAnalyzer) Analyze() []AttackPath {
	var paths []AttackPath

	entryPoints := a.IdentifyEntryPoints()
	if len(entryPoints) == 0 {
		return paths
	}

	escalationPaths := a.IdentifyEscalationPaths(entryPoints)

	// Deduplicate paths by generating deterministic IDs
	seen := make(map[string]bool)
	for _, path := range escalationPaths {
		id := generatePathID(path)
		if !seen[id] {
			seen[id] = true
			path.ID = id
			paths = append(paths, path)
		}
	}

	// Sort paths by overall CVSS descending for deterministic output
	sort.Slice(paths, func(i, j int) bool {
		if paths[i].OverallCVSS != paths[j].OverallCVSS {
			return paths[i].OverallCVSS > paths[j].OverallCVSS
		}
		return paths[i].Name < paths[j].Name
	})

	return paths
}

// ChainByURL groups findings by URL and identifies relationships
func (a *AttackPathAnalyzer) ChainByURL() map[string][]Finding {
	groups := make(map[string][]Finding)
	for _, f := range a.findings {
		parsed, err := url.Parse(f.URL)
		if err != nil {
			// Use the raw URL as key if parsing fails
			groups[f.URL] = append(groups[f.URL], f)
			continue
		}
		// Group by scheme + host (ignore path/query for grouping)
		key := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
		groups[key] = append(groups[key], f)
	}

	// Sort findings within each group by severity for deterministic output
	for key := range groups {
		sort.Slice(groups[key], func(i, j int) bool {
			return severityOrder(groups[key][i].Severity) > severityOrder(groups[key][j].Severity)
		})
	}

	return groups
}

// IdentifyEntryPoints finds findings that could be initial attack vectors
func (a *AttackPathAnalyzer) IdentifyEntryPoints() []Finding {
	var entryPoints []Finding

	for _, f := range a.findings {
		if _, ok := entryPointScanners[f.Scanner]; ok {
			entryPoints = append(entryPoints, f)
		}
	}

	// Sort by severity for deterministic output
	sort.Slice(entryPoints, func(i, j int) bool {
		if severityOrder(entryPoints[i].Severity) != severityOrder(entryPoints[j].Severity) {
			return severityOrder(entryPoints[i].Severity) > severityOrder(entryPoints[j].Severity)
		}
		return entryPoints[i].Scanner < entryPoints[j].Scanner
	})

	return entryPoints
}

// IdentifyEscalationPaths finds paths from entry points to high-impact findings
func (a *AttackPathAnalyzer) IdentifyEscalationPaths(entryPoints []Finding) []AttackPath {
	var paths []AttackPath

	// Build a lookup of findings by scanner name for quick chaining
	findingsByScanner := make(map[string][]Finding)
	for _, f := range a.findings {
		findingsByScanner[f.Scanner] = append(findingsByScanner[f.Scanner], f)
	}

	// For each entry point, follow chain rules to build paths
	for _, ep := range entryPoints {
		path := buildPathFromEntry(ep, findingsByScanner, nil)
		if len(path.Steps) >= 2 {
			paths = append(paths, path)
		}

		// Also try multi-step chains (depth-first, max depth 4)
		extendedPaths := buildExtendedPaths(ep, findingsByScanner, 4)
		for _, p := range extendedPaths {
			if len(p.Steps) >= 2 {
				paths = append(paths, p)
			}
		}
	}

	return paths
}

// buildPathFromEntry builds a single attack path starting from an entry point
func buildPathFromEntry(entry Finding, findingsByScanner map[string][]Finding, visited map[string]bool) AttackPath {
	if visited == nil {
		visited = make(map[string]bool)
	}
	visited[entry.Scanner] = true

	step := PathStep{
		Finding:     entry,
		Role:        getRole(entry.Scanner, true),
		Description: describeStep(entry, true),
	}

	// Find what this entry point can chain to
	var nextSteps []PathStep
	for _, rule := range chainRules {
		if rule.From == entry.Scanner {
			if visited[rule.To] {
				continue
			}
			if nextFindings, ok := findingsByScanner[rule.To]; ok && len(nextFindings) > 0 {
				next := nextFindings[0] // Take the first matching finding
				nextStep := PathStep{
					Finding:     next,
					Role:        getRole(next.Scanner, false),
					Description: rule.Description,
					EnablesNext:  rule.To,
				}
				step.EnablesNext = rule.To
				nextSteps = append(nextSteps, nextStep)
			}
		}
	}

	steps := []PathStep{step}
	steps = append(steps, nextSteps...)

	name := fmt.Sprintf("Attack path via %s", entry.Scanner)
	if len(nextSteps) > 0 {
		name = fmt.Sprintf("%s → %s chain", entry.Scanner, nextSteps[0].Finding.Scanner)
	}

	return AttackPath{
		Name:             name,
		Description:      buildDescription(steps),
		Steps:            steps,
		OverallRisk:      calculateOverallRisk(steps),
		OverallCVSS:      calculateOverallCVSS(steps),
		AttackComplexity: calculateAttackComplexity(steps),
	}
}

// buildExtendedPaths builds multi-step attack paths using depth-first traversal
func buildExtendedPaths(entry Finding, findingsByScanner map[string][]Finding, maxDepth int) []AttackPath {
	var paths []AttackPath
	visited := map[string]bool{entry.Scanner: true}
	currentPath := []PathStep{
		{
			Finding:     entry,
			Role:        getRole(entry.Scanner, true),
			Description: describeStep(entry, true),
		},
	}

	dfsBuildPaths(entry.Scanner, findingsByScanner, visited, currentPath, maxDepth, &paths)

	return paths
}

// dfsBuildPaths recursively builds attack paths using depth-first search
func dfsBuildPaths(currentScanner string, findingsByScanner map[string][]Finding, visited map[string]bool, currentPath []PathStep, maxDepth int, paths *[]AttackPath) {
	if len(currentPath) >= maxDepth {
		return
	}

	for _, rule := range chainRules {
		if rule.From != currentScanner {
			continue
		}
		if visited[rule.To] {
			continue
		}
		if nextFindings, ok := findingsByScanner[rule.To]; ok && len(nextFindings) > 0 {
			next := nextFindings[0]
			visited[rule.To] = true

			step := PathStep{
				Finding:     next,
				Role:        getRole(next.Scanner, false),
				Description: rule.Description,
				EnablesNext:  rule.To,
			}

			// Update previous step's EnablesNext
			newPath := make([]PathStep, len(currentPath))
			copy(newPath, currentPath)
			if len(newPath) > 0 {
				newPath[len(newPath)-1].EnablesNext = rule.To
			}
			newPath = append(newPath, step)

			// Only add paths with 2+ steps
			if len(newPath) >= 2 {
				name := buildPathName(newPath)
				*paths = append(*paths, AttackPath{
					Name:             name,
					Description:      buildDescription(newPath),
					Steps:            newPath,
					OverallRisk:      calculateOverallRisk(newPath),
					OverallCVSS:      calculateOverallCVSS(newPath),
					AttackComplexity: calculateAttackComplexity(newPath),
				})
			}

			// Continue DFS
			dfsBuildPaths(rule.To, findingsByScanner, visited, newPath, maxDepth, paths)

			// Backtrack
			delete(visited, rule.To)
		}
	}
}

// calculateOverallRisk determines the overall risk level of an attack path
func calculateOverallRisk(steps []PathStep) Severity {
	if len(steps) == 0 {
		return SeverityInfo
	}

	// Find the maximum severity among all steps
	maxSeverity := SeverityInfo
	for _, step := range steps {
		if severityOrder(step.Finding.Severity) > severityOrder(maxSeverity) {
			maxSeverity = step.Finding.Severity
		}
	}

	// Boost by 1 level if 3+ steps (shows attack complexity makes it more dangerous)
	if len(steps) >= 3 {
		maxSeverity = boostSeverity(maxSeverity)
	}

	return maxSeverity
}

// calculateOverallCVSS computes the overall CVSS score for an attack path
func calculateOverallCVSS(steps []PathStep) float64 {
	if len(steps) == 0 {
		return 0.0
	}

	// Find the highest step CVSS
	maxCVSS := 0.0
	for _, step := range steps {
		if step.Finding.CVSSScore > maxCVSS {
			maxCVSS = step.Finding.CVSSScore
		}
	}

	// Overall CVSS = highest step CVSS + 0.5 * (number_of_steps - 1), capped at 10.0
	overall := maxCVSS + 0.5*float64(len(steps)-1)
	if overall > 10.0 {
		overall = 10.0
	}

	return overall
}

// calculateAttackComplexity determines the attack complexity based on URL diversity
func calculateAttackComplexity(steps []PathStep) string {
	hostSet := make(map[string]bool)
	for _, step := range steps {
		parsed, err := url.Parse(step.Finding.URL)
		if err != nil {
			hostSet[step.Finding.URL] = true
			continue
		}
		hostSet[fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)] = true
	}

	switch len(hostSet) {
	case 1:
		return "low"
	case 2, 3:
		return "medium"
	default:
		return "high"
	}
}

// severityOrder maps Severity to a numeric value for comparison
func severityOrder(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// boostSeverity increases severity by one level
func boostSeverity(s Severity) Severity {
	switch s {
	case SeverityLow:
		return SeverityMedium
	case SeverityMedium:
		return SeverityHigh
	case SeverityHigh:
		return SeverityCritical
	case SeverityCritical:
		return SeverityCritical // Can't go higher
	default:
		return SeverityLow
	}
}

// describeStep generates a human-readable description for a finding's role
func describeStep(f Finding, isEntry bool) string {
	if isEntry {
		switch f.Scanner {
		case "Cross-Site Scripting (XSS)":
			return "Reflected input allows session hijacking as initial access vector"
		case "SQL Injection":
			return "SQL injection provides database access for credential theft"
		case "Server-Side Request Forgery (SSRF)":
			return "SSRF enables internal network access for privilege escalation"
		case "Authentication Failures":
			return "Default or weak credentials provide initial access"
		case "CORS Misconfiguration":
			return "CORS misconfiguration allows cross-origin data access"
		case "Open Redirect":
			return "Open redirect enables phishing for credential harvesting"
		default:
			return fmt.Sprintf("%s serves as initial attack vector", f.Scanner)
		}
	}
	return fmt.Sprintf("%s enables further exploitation", f.Scanner)
}

// buildDescription creates a description for the full attack path
func buildDescription(steps []PathStep) string {
	if len(steps) == 0 {
		return ""
	}
	if len(steps) == 1 {
		return steps[0].Description
	}

	var parts []string
	for i, step := range steps {
		if i == 0 {
			parts = append(parts, step.Description)
		} else {
			parts = append(parts, fmt.Sprintf("Then, %s", strings.ToLower(step.Description[:1])+step.Description[1:]))
		}
	}
	return strings.Join(parts, ". ") + "."
}

// buildPathName creates a descriptive name for the attack path
func buildPathName(steps []PathStep) string {
	names := make([]string, 0, len(steps))
	seen := make(map[string]bool)
	for _, step := range steps {
		if !seen[step.Finding.Scanner] {
			names = append(names, step.Finding.Scanner)
			seen[step.Finding.Scanner] = true
		}
	}
	return strings.Join(names, " → ") + " attack chain"
}

// generatePathID creates a deterministic ID for an attack path
func generatePathID(path AttackPath) string {
	var parts []string
	for _, step := range path.Steps {
		parts = append(parts, step.Finding.Scanner)
	}
	// Use timestamp from first finding for uniqueness
	ts := ""
	if len(path.Steps) > 0 {
		ts = path.Steps[0].Finding.Timestamp.Format("20060102")
	}
	return fmt.Sprintf("AP-%s-%s", ts, strings.Join(parts, "-"))
}

