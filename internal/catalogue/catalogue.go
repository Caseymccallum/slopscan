// Package catalogue is the local database of every MCP server and tool scanned.
//
// This is deliberately a database rather than a report: the point of scanning is to accumulate a
// private, queryable picture of the ecosystem on one's own machine - what a server exposes, how it
// was classified, when it was last seen - with no phone-home and no shared telemetry. SQLite in
// pure Go (`modernc.org/sqlite`), one file, no service to run.
package catalogue

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, registered as "sqlite"

	"github.com/Caseymccallum/slopscan/internal/injection"
	"github.com/Caseymccallum/slopscan/internal/risk"
)

// Catalogue is one scan database: servers, their tools, and the findings on each tool.
type Catalogue struct {
	db *sql.DB
}

// Server is one MCP server as the catalogue remembers it.
type Server struct {
	ID          string    `json:"id"`
	Source      string    `json:"source"`
	Tools       int       `json:"tools"`
	WorstWeight float64   `json:"worstWeight"`
	ScannedAt   time.Time `json:"scannedAt"`
}

// Open opens (and on first run creates) the scan database at path.
func Open(path string) (*Catalogue, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// WAL so a scan can run while a report reads; foreign keys on because tool rows reference
	// their server and a half-written scan should not leave orphans.
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;`); err != nil {
		_ = db.Close()
		return nil, err
	}
	schema := `
CREATE TABLE IF NOT EXISTS servers (
  id TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  scanned_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tools (
  server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  weight REAL NOT NULL,
  confidence TEXT NOT NULL,
  reasons TEXT NOT NULL,
  definition TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (server_id, name)
);
-- The baseline deliberately has no foreign key to servers: a re-scan replaces the servers row
-- (that is how a new observation supersedes an old one), and a pinned baseline must survive that.
-- A baseline dies when a person re-pins, never because something was scanned again.
CREATE TABLE IF NOT EXISTS baselines (
  server_id TEXT PRIMARY KEY,
  pinned_at TEXT NOT NULL,
  tools_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
  server_id TEXT NOT NULL,
  tool_name TEXT NOT NULL,
  where_found TEXT NOT NULL,
  kind TEXT NOT NULL,
  owasp TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL,
  quote TEXT NOT NULL
);
-- History is append-only and, like the baseline, deliberately has no foreign key to servers: a
-- re-scan replaces the servers row (that is how a new observation supersedes an old one), and the
-- record of what was seen when must survive it. A re-scan is a new row here even though it is a
-- replacement up there - the timeline is the half of the story that only grows.
CREATE TABLE IF NOT EXISTS history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  server_id TEXT NOT NULL,
  scanned_at TEXT NOT NULL,
  tool_count INTEGER NOT NULL,
  risk REAL NOT NULL,
  surface TEXT NOT NULL,
  -- The tool definitions are stored when the surface differs from the row before and left empty
  -- when it does not: an unchanged observation is carried by the last row that changed. A watch
  -- loop must not grow the file by a copy of the tool list every tick.
  tools_json TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS findings_by_server ON findings(server_id);
CREATE INDEX IF NOT EXISTS history_by_server ON history(server_id);
CREATE INDEX IF NOT EXISTS tools_by_weight ON tools(weight);
`
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Catalogue{db: db}, nil
}

// Close releases the database.
func (c *Catalogue) Close() error { return c.db.Close() }

// Record stores the verdict for one server, replacing any earlier scan of the same id: a re-scan
// is a new observation of the same thing, not a second thing. The raw tool definitions are stored
// alongside the verdicts, because drift comparison needs the server's own words - the assessment
// says what was thought of them, the definition is what they were.
func (c *Catalogue) Record(
	serverID, source string,
	tools []risk.Tool,
	assessments []risk.Assessment,
	findings map[string][]injection.Finding,
) error {
	definitions := map[string]string{}
	for _, tool := range tools {
		raw, _ := json.Marshal(tool)
		definitions[tool.Name] = string(raw)
	}

	tx, err := c.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`DELETE FROM servers WHERE id = ?`, serverID); err != nil {
		return err
	}
	// Findings are cleared here too rather than left to a cascade: a re-scan replaces the whole
	// observation, and findings that outlived their scan would pile up under one server until the
	// report said three times what it means once.
	if _, err := tx.Exec(`DELETE FROM findings WHERE server_id = ?`, serverID); err != nil {
		return err
	}
	if _, err := tx.Exec(
		`INSERT INTO servers (id, source, scanned_at) VALUES (?, ?, ?)`,
		serverID, source, time.Now().UTC().Format(time.RFC3339),
	); err != nil {
		return err
	}

	for _, assessment := range assessments {
		reasons, _ := json.Marshal(assessment.Reasons)
		if _, err := tx.Exec(
			`INSERT INTO tools (server_id, name, category, weight, confidence, reasons, definition) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			serverID, assessment.Tool, assessment.Category, assessment.Weight, assessment.Confidence, reasons,
			definitions[assessment.Tool],
		); err != nil {
			return err
		}
		for _, finding := range findings[assessment.Tool] {
			if _, err := tx.Exec(
				`INSERT INTO findings (server_id, tool_name, where_found, kind, owasp, severity, quote) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				serverID, assessment.Tool, finding.Where, finding.Kind, finding.OWASP, finding.Severity, finding.Quote,
			); err != nil {
				return err
			}
		}
	}

	// The timeline grows even though the verdict is replaced: one row per scan, so "when did this
	// change?" has an answer. Definitions are stored only when the surface differs from the row
	// before - unchanged scans are the common case and a watch loop is a copy machine otherwise.
	totalWeight := 0.0
	for _, assessment := range assessments {
		totalWeight += assessment.Weight
	}
	surface := risk.SurfaceFingerprint(tools)
	previous := ""
	_ = tx.QueryRow(`SELECT surface FROM history WHERE server_id = ? ORDER BY id DESC LIMIT 1`, serverID).Scan(&previous)
	stored := ""
	if surface != previous {
		raw, _ := json.Marshal(tools)
		stored = string(raw)
	}
	if _, err := tx.Exec(
		`INSERT INTO history (server_id, scanned_at, tool_count, risk, surface, tools_json) VALUES (?, ?, ?, ?, ?, ?)`,
		serverID, time.Now().UTC().Format(time.RFC3339), len(tools), totalWeight, surface, stored,
	); err != nil {
		return err
	}

	return tx.Commit()
}

// Source returns where a scanned server's tools came from, or "" when it is unknown.
func (c *Catalogue) Source(serverID string) (string, error) {
	var source string
	err := c.db.QueryRow(`SELECT source FROM servers WHERE id = ?`, serverID).Scan(&source)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return source, err
}

// Pin freezes the server's current tool definitions as the reviewed baseline: the copy every later
// scan is compared against. Pinning is a deliberate act ("this is what I reviewed"), not an
// automatic side effect of scanning - the whole point is that the baseline changes only when a
// person says so.
func (c *Catalogue) Pin(serverID string) error {
	definitions, err := c.Definitions(serverID)
	if err != nil {
		return err
	}
	if len(definitions) == 0 {
		return fmt.Errorf("nothing to pin: %s has no scanned tools", serverID)
	}

	raw, err := json.Marshal(definitions)
	if err != nil {
		return err
	}

	tx, err := c.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`DELETE FROM baselines WHERE server_id = ?`, serverID); err != nil {
		return err
	}
	if _, err := tx.Exec(
		`INSERT INTO baselines (server_id, pinned_at, tools_json) VALUES (?, ?, ?)`,
		serverID, time.Now().UTC().Format(time.RFC3339), raw,
	); err != nil {
		return err
	}
	return tx.Commit()
}

// Baseline returns the pinned tool definitions for a server, or nil when nothing has been pinned.
func (c *Catalogue) Baseline(serverID string) ([]risk.Tool, error) {
	var raw string
	err := c.db.QueryRow(`SELECT tools_json FROM baselines WHERE server_id = ?`, serverID).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var tools []risk.Tool
	if err := json.Unmarshal([]byte(raw), &tools); err != nil {
		return nil, err
	}
	return tools, nil
}

// Definitions returns the raw tool definitions recorded for one server - the server's own words,
// kept so drift can compare what was reviewed with what is being said now.
func (c *Catalogue) Definitions(serverID string) ([]risk.Tool, error) {
	rows, err := c.db.Query(`SELECT definition FROM tools WHERE server_id = ? ORDER BY name`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tools := []risk.Tool{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var tool risk.Tool
		if err := json.Unmarshal([]byte(raw), &tool); err != nil {
			return nil, err
		}
		tools = append(tools, tool)
	}
	return tools, rows.Err()
}

// Servers lists every scanned server, riskiest first.
func (c *Catalogue) Servers() ([]Server, error) {
	rows, err := c.db.Query(`
SELECT s.id, s.source, COUNT(t.name), COALESCE(MAX(t.weight), 0), s.scanned_at
FROM servers s LEFT JOIN tools t ON t.server_id = s.id
GROUP BY s.id ORDER BY COALESCE(MAX(t.weight), 0) DESC, s.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	servers := []Server{}
	for rows.Next() {
		var server Server
		var scannedAt string
		if err := rows.Scan(&server.ID, &server.Source, &server.Tools, &server.WorstWeight, &scannedAt); err != nil {
			return nil, err
		}
		server.ScannedAt, _ = time.Parse(time.RFC3339, scannedAt)
		servers = append(servers, server)
	}
	return servers, rows.Err()
}

// Tools returns every tool recorded for one server, most dangerous first.
func (c *Catalogue) Tools(serverID string) ([]risk.Assessment, error) {
	rows, err := c.db.Query(
		`SELECT name, category, weight, confidence, reasons FROM tools
WHERE server_id = ? ORDER BY weight DESC, name`,
		serverID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tools := []risk.Assessment{}
	for rows.Next() {
		var assessment risk.Assessment
		var reasons string
		if err := rows.Scan(&assessment.Tool, &assessment.Category, &assessment.Weight, &assessment.Confidence, &reasons); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(reasons), &assessment.Reasons)
		tools = append(tools, assessment)
	}
	return tools, rows.Err()
}

// Findings returns every injection finding recorded for one server.
func (c *Catalogue) Findings(serverID string) (map[string][]injection.Finding, error) {
	rows, err := c.db.Query(
		`SELECT tool_name, where_found, kind, owasp, severity, quote FROM findings WHERE server_id = ?`,
		serverID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	findings := map[string][]injection.Finding{}
	for rows.Next() {
		var toolName string
		var finding injection.Finding
		if err := rows.Scan(&toolName, &finding.Where, &finding.Kind, &finding.OWASP, &finding.Severity, &finding.Quote); err != nil {
			return nil, err
		}
		findings[toolName] = append(findings[toolName], finding)
	}
	return findings, rows.Err()
}

// Observation is one scan as the timeline remembers it.
type Observation struct {
	ID        int64     `json:"id"`
	ScannedAt time.Time `json:"scannedAt"`
	Tools     int       `json:"tools"`
	Risk      float64   `json:"risk"`
	Surface   string    `json:"surface"`
	// Definitions is the tool list as of this scan. Unchanged observations store no copy of
	// their own (see the schema); they carry the definitions forward from the last row that did.
	Definitions []risk.Tool `json:"definitions"`
}

// History returns every observation of one server, oldest first: the timeline that answers "when
// did this change?" - the question the verdict table cannot, because a re-scan replaces it.
func (c *Catalogue) History(serverID string) ([]Observation, error) {
	rows, err := c.db.Query(
		`SELECT id, scanned_at, tool_count, risk, surface, tools_json FROM history
 WHERE server_id = ? ORDER BY id`, serverID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	observations := []Observation{}
	carried := []risk.Tool{}
	for rows.Next() {
		var observation Observation
		var scannedAt, stored string
		if err := rows.Scan(&observation.ID, &scannedAt, &observation.Tools, &observation.Risk,
			&observation.Surface, &stored); err != nil {
			return nil, err
		}
		observation.ScannedAt, _ = time.Parse(time.RFC3339, scannedAt)
		if stored != "" {
			carried = nil
			if err := json.Unmarshal([]byte(stored), &carried); err != nil {
				return nil, err
			}
		}
		observation.Definitions = carried
		observations = append(observations, observation)
	}
	return observations, rows.Err()
}