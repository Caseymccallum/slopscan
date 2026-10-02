package registry

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestExistingNameIsFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/react" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"name":"react","versions":{}}`))
	}))
	defer server.Close()

	result, err := (Checker{Base: server.URL}).Exists("react")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Exists {
		t.Error("published package reported missing")
	}
}

// The whole point: a name nothing has ever published is exactly what a slopsquat needs.
func TestMissingNameIsMissing(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	result, err := (Checker{Base: server.URL}).Exists("left-padd-async")
	if err != nil {
		t.Fatal(err)
	}
	if result.Exists {
		t.Error("unpublished package reported as existing")
	}
}

// A flaky registry is reported per name, and does not stop the names that could be checked.
func TestCheckAllSurvivesFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/boom" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"name":"x","versions":{}}`))
	}))
	defer server.Close()

	results := (Checker{Base: server.URL}).CheckAll([]string{"boom", "good"})
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	if results[0].Error == "" {
		t.Error("failed lookup carries no error")
	}
	if !results[1].Exists {
		t.Error("good lookup was not reported")
	}
}

// PyPI answers at /pypi/<name>/json: a suffix is part of the registry's address, not a
// transformation of the name (which this package refuses to guess at).
func TestSuffixIsAppendedToTheLookupURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/requests/json" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"info":{"name":"requests"}}`))
	}))
	defer server.Close()

	result, err := (Checker{Base: server.URL, Suffix: "/json"}).Exists("requests")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Exists {
		t.Error("suffixed lookup did not find the package")
	}
}

// The facts a slopsquat cannot rewrite: when the package appeared and how much is under it.
func TestPackumentFactsTravel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"x","time":{"created":"2026-09-28T10:00:00Z"},
			"versions":{"1.0.0":{}}}`))
	}))
	defer server.Close()

	result, err := (Checker{Base: server.URL}).Exists("x")
	if err != nil {
		t.Fatal(err)
	}
	if result.Created.Year() != 2026 || result.Created.Month() != 9 {
		t.Errorf("creation date lost: %+v", result)
	}
	if result.Versions != 1 {
		t.Errorf("version count lost: %+v", result)
	}
}

// PyPI's format differs (releases with upload times); the facts are the same two facts.
func TestPyPIPackumentFactsTravel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"info":{"name":"x"},"releases":{
			"1.0.0":[{"upload_time_iso_8601":"2026-09-28T10:00:00Z"}],
			"1.0.1":[{"upload_time_iso_8601":"2026-09-29T10:00:00Z"}]}}`))
	}))
	defer server.Close()

	result, err := (Checker{Base: server.URL, Suffix: "/json"}).Exists("x")
	if err != nil {
		t.Fatal(err)
	}
	if result.Versions != 2 {
		t.Errorf("release count wrong: %+v", result)
	}
	if result.Created.Day() != 28 {
		t.Errorf("earliest upload not the creation: %+v", result)
	}
}

// A name is compared by its bones: separators and case are exactly what a squatter flips.
func TestNearFindsTheSquatShape(t *testing.T) {
	for name, want := range map[string]string{
		"lodsh":            "lodash",
		"mcp_server_github": "mcp-server-github",
		"McP-Weather":      "mcp-weather",
	} {
		neighbor, relation := Near("npm", name)
		if neighbor != want {
			t.Errorf("Near(npm, %q) = %q (%q), want %q", name, neighbor, relation, want)
		}
	}
	if _, relation := Near("npm", "mcp_server_github"); relation == "" {
		t.Error("separator variant should carry a relation")
	}

	// The real name is not its own lookalike, and a genuinely different name is quiet.
	if neighbor, _ := Near("npm", "lodash"); neighbor != "" {
		t.Errorf("the real name flagged as its own lookalike: %q", neighbor)
	}
	if neighbor, _ := Near("npm", "totally-unrelated-package-xyz"); neighbor != "" {
		t.Errorf("an unrelated name flagged: %q", neighbor)
	}
}

// The window is a month: inside it, the age is stated as fact; outside it, silence.
func TestFreshnessWindow(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	fresh := Result{Created: now.Add(-3 * 24 * time.Hour), Versions: 1}
	if got := Freshness(fresh, now); !strings.Contains(got, "3 day(s) ago") {
		t.Errorf("fresh package not described: %q", got)
	}
	old := Result{Created: now.Add(-200 * 24 * time.Hour), Versions: 40}
	if got := Freshness(old, now); got != "" {
		t.Errorf("an old package described as fresh: %q", got)
	}
	unknown := Result{}
	if got := Freshness(unknown, now); got != "" {
		t.Errorf("an unknown age described: %q", got)
	}
}