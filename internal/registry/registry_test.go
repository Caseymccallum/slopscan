package registry

import (
	"net/http"
	"net/http/httptest"
	"testing"
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