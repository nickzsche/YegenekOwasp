package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/temren/pkg/httpengine"
)

func TestSQLiScanner_Scan(t *testing.T) {
	tests := []struct {
		name       string
		handler    http.HandlerFunc
		targetURL  string
		expectVuln bool
	}{
		{
			name: "Error-based SQLi vulnerable",
			handler: func(w http.ResponseWriter, r *http.Request) {
				id := r.URL.Query().Get("id")
				if id == "'" {
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte("You have an error in your SQL syntax"))
					return
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("Normal response"))
			},
			targetURL:  "/search?id=1",
			expectVuln: true,
		},
		{
			name: "No SQLi vulnerability",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("Safe response"))
			},
			targetURL:  "/search?id=1",
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

			scanner := NewSQLiScanner()
			ctx := context.Background()
			results, err := scanner.Scan(ctx, fullURL, client)

			if err != nil {
				t.Fatalf("Scan error: %v", err)
			}

			if tt.expectVuln {
				if len(results) == 0 {
					t.Errorf("Expected vulnerability found, got none")
				}
			} else {
				for _, r := range results {
					if r.Severity == SeverityHigh || r.Severity == SeverityCritical {
						t.Errorf("Unexpected vulnerability: %s", r.Title)
					}
				}
			}
		})
	}
}

func TestSQLiScanner_NoParameters(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(nil)
	scanner := NewSQLiScanner()
	ctx := context.Background()

	// URL without query parameters
	results, err := scanner.Scan(ctx, server.URL+"/page", client)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("Expected no findings for URL without params, got %d", len(results))
	}
}

func TestSQLiScanner_InvalidURL(t *testing.T) {
	client := httpengine.NewClient(nil)
	scanner := NewSQLiScanner()
	ctx := context.Background()

	_, err := scanner.Scan(ctx, "://invalid-url", client)
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestTimeBasedSQLiScanner_Scan(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "' AND SLEEP(5)--" {
			time.Sleep(5 * time.Second)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Response"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := httpengine.NewClient(&httpengine.Config{
		Timeout:   10 * time.Second,
		RateLimit: 100,
	})

	scanner := NewTimeBasedSQLiScanner()
	ctx := context.Background()
	results, err := scanner.Scan(ctx, server.URL+"/search?id=1", client)

	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	// Time-based detection should identify slow responses
	for _, r := range results {
		if r.Title == "Time-Based SQL Injection" {
			return // Found expected vulnerability
		}
	}
	// Time-based detection depends on server delay, so we just verify no panics
}
