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
	Name   string `json:"name"`
	Exists bool   `json:"exists"`
	// Created is when the package first appeared in the registry, zero when the registry did
	// not say. Age is the fact a slopsquat cannot rewrite after publishing: the window in
	// which a name is registered and waited on is exactly the window this records.
	Created time.Time `json:"created"`
	// Versions is how much has been published under the name (zero when unknown): one version
	// registered days ago is the shape of a name made to be fetched once.
	Versions int `json:"versions"`
	// Populated when the registry answered but could not be understood, or did not answer.
	Error string `json:"error,omitempty"`
}

// Checker looks package names up in one registry.
type Checker struct {
	// Base is the registry's package-info endpoint, e.g. https://registry.npmjs.org.
	Base string
	// Suffix is appended after the name in the lookup URL, for registries whose API wants one
	// (PyPI answers at /pypi/<name>/json). npm wants none.
	Suffix string
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

	target := strings.TrimRight(c.Base, "/") + "/" + url.PathEscape(name) + c.Suffix
	response, err := client.Get(target)
	if err != nil {
		return Result{Name: name, Error: err.Error()}, err
	}
	defer response.Body.Close()

	switch {
	case response.StatusCode == http.StatusOK:
		// The body is the packument. Existence is the first answer; the facts it carries
		// about when and how much was published are the second - they are what separates a
		// package someone depends on from a name someone registered last week.
		var packument map[string]any
		if err := json.NewDecoder(response.Body).Decode(&packument); err != nil {
			return Result{Name: name, Error: "registry sent a response that could not be read"}, err
		}
		created, versions := packumentFacts(packument)
		return Result{Name: name, Exists: true, Created: created, Versions: versions}, nil
	case response.StatusCode == http.StatusNotFound:
		return Result{Name: name, Exists: false}, nil
	default:
		return Result{Name: name, Error: fmt.Sprintf("registry answered %d", response.StatusCode)},
			fmt.Errorf("registry answered %d for %s", response.StatusCode, name)
	}
}

// packumentFacts pulls the two facts a package record carries in either ecosystem's format:
// npm stamps `time.created` and counts `versions`; PyPI counts `releases` and stamps each
// upload. A registry that answers with neither simply did not say, and zero is the answer.
func packumentFacts(packument map[string]any) (time.Time, int) {
	var created time.Time
	versions := 0

	if timing, ok := packument["time"].(map[string]any); ok {
		if stamp, ok := timing["created"].(string); ok {
			created, _ = time.Parse(time.RFC3339, stamp)
		}
	}
	if listed, ok := packument["versions"].(map[string]any); ok {
		versions = len(listed)
	}

	// PyPI: {"releases": {"1.0": [{"upload_time_iso_8601": "..."}]}} - the package appeared
	// when its earliest release was uploaded.
	if releases, ok := packument["releases"].(map[string]any); ok {
		versions = len(releases)
		for _, uploads := range releases {
			list, _ := uploads.([]any)
			for _, upload := range list {
				fields, _ := upload.(map[string]any)
				stamp, _ := fields["upload_time_iso_8601"].(string)
				when, err := time.Parse(time.RFC3339, stamp)
				if err != nil {
					continue
				}
				if created.IsZero() || when.Before(created) {
					created = when
				}
			}
		}
	}
	return created, versions
}

// FreshWindow is how long a package stays "fresh". A slopsquat is registered and waited on -
// the research's attack is patient by construction - so a name fetched days after it appeared
// is exactly the case worth a second look. A month is the documented line; older packages are
// ordinary and say nothing.
const FreshWindow = 30 * 24 * time.Hour

// Freshness describes a package's age in the terms the slopsquat question asks, or "" when the
// package is too old to be interesting or the registry did not say. The description is facts
// (date, age, count) - the judgement is the reader's.
func Freshness(result Result, now time.Time) string {
	if result.Created.IsZero() {
		return ""
	}
	age := now.Sub(result.Created)
	if age > FreshWindow {
		return ""
	}
	days := int(age.Hours() / 24)
	if days < 0 {
		days = 0 // a clock difference is not evidence of anything
	}
	return fmt.Sprintf("was published %s (%d day(s) ago, %d version(s))",
		result.Created.Format("2006-01-02"), days, result.Versions)
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