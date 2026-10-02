// Package registry checks whether a package name exists before anything installs it.
//
// The attack is slopsquatting: a model suggests a package that does not exist, an attacker publishes
// one under that name, and the next `npm install` runs their code. The defence is small and
// unglamorous - look the name up first - so it lives here as one function with an injectable
// endpoint, and the tests run against fixtures rather than the real registry.
package registry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Result is what a lookup found.
type Result struct {
	Name     string `json:"name"`
	Exists   bool   `json:"exists"`
	// Populated when the registry answered but could not be understood, or did not answer.
	Error string `json:"error,omitempty"`
}

// Checker looks package names up in one registry.
type Checker struct {
	// Base is the registry's package-info endpoint, e.g. https://registry.npmjs.org.
	Base string
	// Client is the HTTP client to use; nil means a client with a 10s timeout.
	Client *http.Client
}

// Exists reports whether a package name is published, without ever suggesting one.
//
// The name is sent exactly as given - this function does not normalise, prefix or "fix" it, because
// any transformation would be a guess about what the caller meant, and guessing is the disease.
func (c Checker) Exists(name string) (Result, error) {
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	target := strings.TrimRight(c.Base, "/") + "/" + url.PathEscape(name)
	response, err := client.Get(target)
	if err != nil {
		return Result{Name: name, Error: err.Error()}, err
	}
	defer response.Body.Close()

	switch {
	case response.StatusCode == http.StatusOK:
		// The body is the packument; its existence is the answer, its contents are not needed.
		var packument map[string]any
		if err := json.NewDecoder(response.Body).Decode(&packument); err != nil {
			return Result{Name: name, Error: "registry sent a response that could not be read"}, err
		}
		return Result{Name: name, Exists: true}, nil
	case response.StatusCode == http.StatusNotFound:
		return Result{Name: name, Exists: false}, nil
	default:
		return Result{Name: name, Error: fmt.Sprintf("registry answered %d", response.StatusCode)},
			fmt.Errorf("registry answered %d for %s", response.StatusCode, name)
	}
}

// CheckAll looks up every name and returns the results in order. A lookup that fails entirely is
// reported as an error on that result rather than aborting the run: a flaky registry should not
// stop the names that could be checked.
func (c Checker) CheckAll(names []string) []Result {
	results := make([]Result, 0, len(names))
	for _, name := range names {
		result, err := c.Exists(name)
		if err != nil && result.Error == "" {
			result.Error = err.Error()
		}
		results = append(results, result)
	}
	return results
}