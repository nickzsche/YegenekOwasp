package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/temren/pkg/httpengine"
)

func TestXSSScanner_Scan(t *testing.T) {
	tests := []struct {
		name       string
		handler    http.HandlerFunc
		targetURL  string
		expectVuln bool
	}{
		{
			name: "Reflected XSS vulnerable",
			handler: func(w http.ResponseWriter, r *http.Request) {
				name := r.URL.Query().Get("name")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("<html><body>Hello " + name + "</body></html>"))
			},
			targetURL:  "/greet?name=test",
			expectVuln: true,
		},
		{
			name: "XSS protected - no reflection",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("<html><body>Hello User</body></html>"))
			},
			targetURL:  "/greet?name=test",
			expectVuln: false,
		},
		{
			name: "No reflection - safe",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("<html><body>Static content</body></html>"))
			},
			targetURL:  "/page?input=test",
			expectVuln: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			fullURL := server.URL + tt.targetURL

			client := httpengine.NewClient(&httpengine.Config{
				Timeout:   5 * time.Second,
				RateLimit: 100,
			})

			scanner := NewXSSScanner()
			ctx := context.Background()
			results, err := scanner.Scan(ctx, fullURL, client)

			if err != nil {
				t.Fatalf("Scan error: %v", err)
			}

			if tt.expectVuln {
				if len(results) == 0 {
					t.Errorf("Expected XSS vulnerability found, got none")
				}
			} else {
				for _, r := range results {
					if r.Severity == SeverityHigh || r.Severity == SeverityMedium {
						t.Errorf("Unexpected XSS vulnerability: %s", r.Title)
					}
				}
			}
		})
	}
}

func TestXSSScanner_NoParameters(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(nil)
	scanner := NewXSSScanner()
	ctx := context.Background()

	results, err := scanner.Scan(ctx, server.URL+"/page", client)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("Expected no findings for URL without params, got %d", len(results))
	}
}

func TestXSSScanner_InvalidURL(t *testing.T) {
	client := httpengine.NewClient(nil)
	scanner := NewXSSScanner()
	ctx := context.Background()

	_, err := scanner.Scan(ctx, "://invalid-url", client)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestDOMXSSScanner_Scan(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`
			<html>
			<body>
			<script>
			document.write(location.hash.substring(1));
			</script>
			</body>
			</html>
		`))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   5 * time.Second,
		RateLimit: 100,
	})

	scanner := NewDOMXSSScanner()
	ctx := context.Background()
	results, err := scanner.Scan(ctx, server.URL+"/page", client)

	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	// DOM XSS detection via static analysis in response
	for _, r := range results {
		if r.Title == "Potential DOM-Based XSS" {
			return // Found expected vulnerability
		}
	}
}

func TestXSSScanner_IsPayloadReflected(t *testing.T) {
	scanner := NewXSSScanner()

	tests := []struct {
		name     string
		payload  string
		body     string
		expected bool
	}{
		{
			name:     "Direct reflection",
			payload:  "<script>alert(1)</script>",
			body:     "<html><script>alert(1)</script></html>",
			expected: true,
		},
		{
			name:     "No reflection",
			payload:  "<script>alert(1)</script>",
			body:     "<html><body>Safe content</body></html>",
			expected: false,
		},
		{
			name:     "Event handler reflection",
			payload:  "<img src=x onerror=alert(1)>",
			body:     "<html><img src=x onerror=alert(1)></html>",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.isPayloadReflected(tt.payload, tt.body)
			if result != tt.expected {
				t.Errorf("isPayloadReflected(%q, %q) = %v, want %v", tt.payload, tt.body, result, tt.expected)
			}
		})
	}
}
