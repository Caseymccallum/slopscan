package registry

import "strings"

// A typosquat exists. That is the whole problem: the attacker published it, so the existence
// check answers "yes" and waves it through. The facts existence cannot cover are the shape of
// the name (a separator flipped, a letter dropped, a transposition - the mistakes an agent or a
// human makes, published under) and the age of the package. This file covers the shape half:
// the name is compared against well-known names and the distance is quoted. Nothing is
// transformed or "fixed" - comparing is evidence, correcting would be guessing.

// nearCorpus is who the squats are aimed at: packages agents and people most often mistype or
// hallucinate near, per ecosystem. A corpus, not a reputation score - additions welcome, and
// every entry is a name, not a judgement.
var nearCorpus = map[string][]string{
	"npm": {
		"react", "express", "lodash", "axios", "chalk", "commander", "typescript", "vue",
		"next", "left-pad", "mcp-server-github", "mcp-weather",
		"@modelcontextprotocol/server-filesystem", "@modelcontextprotocol/server-github",
		"@modelcontextprotocol/server-everything", "@modelcontextprotocol/server-memory",
	},
	"pypi": {
		"requests", "flask", "django", "numpy", "pandas", "boto3", "urllib3", "fastmcp",
		"mcp-server-github", "mcp-weather",
	},
}

// Near reports the well-known name a package name most resembles and how, or ("", "") when it
// resembles none of them closely enough to be worth a reader's minute.
//
// Separator confusion first (mcp_server_github for mcp-server-github is not a typo, it is a
// strategy), then edit distance - one edit for any name, two for long ones, because two edits
// in "requests" is a different claim from two edits in "flask".
func Near(ecosystem, name string) (neighbor, relation string) {
	target := normalize(name)
	best, bestDistance := "", 0
	for _, known := range nearCorpus[ecosystem] {
		if known == name {
			return "", "" // asking about the real name is asking about the real name
		}
		distance := editDistance(target, normalize(known))
		if distance == 0 {
			return known, "a separator or case variant of"
		}
		limit := 1
		if len(target) >= 8 {
			limit = 2
		}
		if distance > limit {
			continue
		}
		if best == "" || distance < bestDistance || (distance == bestDistance && known < best) {
			best, bestDistance = known, distance
		}
	}
	if best == "" {
		return "", ""
	}
	return best, "a near-miss of"
}

// normalize strips everything that is not a letter or a digit, lowercased: the comparison is
// about the name's bones, and separators and case are exactly what a squatter flips.
func normalize(name string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return -1
		}
	}, name)
}

// editDistance is Levenshtein over two short strings: insertions, deletions, substitutions.
// Kept as two rows because twenty characters do not deserve a matrix dependency.
func editDistance(a, b string) int {
	x, y := []rune(a), []rune(b)
	previous := make([]int, len(y)+1)
	current := make([]int, len(y)+1)
	for j := range previous {
		previous[j] = j
	}
	for i := 1; i <= len(x); i++ {
		current[0] = i
		for j := 1; j <= len(y); j++ {
			cost := 1
			if x[i-1] == y[j-1] {
				cost = 0
			}
			current[j] = min3(previous[j]+1, current[j-1]+1, previous[j-1]+cost)
		}
		previous, current = current, previous
	}
	return previous[len(y)]
}

func min3(a, b, c int) int {
	if b < a {
		a = b
	}
	if c < a {
		a = c
	}
	return a
}