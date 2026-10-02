package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Fingerprints of tool definitions: the stable identity of what a server says it can do.
//
// A fingerprint is how drift is noticed. A server's tool list is re-read on every session and
// trusted again each time, so a server can change its story after review - the rug-pull that
// security research (Deadbugz, August 2026) actively exploits. The defence is to pin the reviewed
// copy and compare every later reading against it, and comparison needs a hash that is stable:
// the same definition must fingerprint the same regardless of who serialised it or in what key
// order. So the hash is over a canonical JSON rendering (json.Marshal of a map sorts keys
// recursively), not over whatever bytes the server happened to send.

// Fingerprint is the SHA-256 of a tool's canonical definition: name, description, input schema,
// and which surface it came from with its address. Every piece of it is reviewable, so every
// piece of it is identity - a resource whose URI moved is a different surface even when its
// description did not change.
func Fingerprint(tool Tool) string {
	canonical, _ := json.Marshal(map[string]any{
		"name":        tool.Name,
		"description": tool.Description,
		"inputSchema": tool.InputSchema,
		"surface":     tool.Surface,
		"uri":         tool.URI,
	})
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

// SurfaceFingerprint is the identity of a whole tool list: the sorted per-tool fingerprints,
// hashed. Two servers with the same tools in different orders are the same surface.
func SurfaceFingerprint(tools []Tool) string {
	fingerprints := make([]string, 0, len(tools))
	for _, tool := range tools {
		fingerprints = append(fingerprints, Fingerprint(tool))
	}
	// Insertion sort of a short list: no dependency worth taking for twenty strings.
	for i := 1; i < len(fingerprints); i++ {
		for j := i; j > 0 && fingerprints[j] < fingerprints[j-1]; j-- {
			fingerprints[j], fingerprints[j-1] = fingerprints[j-1], fingerprints[j]
		}
	}
	sum := sha256.Sum256([]byte(joinWith(fingerprints, "\n")))
	return hex.EncodeToString(sum[:])
}

func joinWith(parts []string, sep string) string {
	out := ""
	for i, part := range parts {
		if i > 0 {
			out += sep
		}
		out += part
	}
	return out
}