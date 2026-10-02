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
  PRIMARY KEY (server_id, name)
);
CREATE TABLE IF NOT EXISTS findings (
  server_id TEXT NOT NULL,
  tool_name TEXT NOT NULL,
  where_found TEXT NOT NULL,
  kind TEXT NOT NULL,
  severity TEXT NOT NULL,
  quote TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS findings_by_server ON findings(server_id);
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
// is a new observation of the same thing, not a second thing.
func (c *Catalogue) Record(
	serverID, source string,
	tools []risk.Assessment,
	findings map[string][]injection.Finding,
) error {
	tx, err := c.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`DELETE FROM servers WHERE id = ?`, serverID); err != nil {
		return err
	}
	if _, err := tx.Exec(
		`INSERT INTO servers (id, source, scanned_at) VALUES (?, ?, ?)`,
		serverID, source, time.Now().UTC().Format(time.RFC3339),
	); err != nil {
		return err
	}

	for _, assessment := range tools {
		reasons, _ := json.Marshal(assessment.Reasons)
		if _, err := tx.Exec(
			`INSERT INTO tools (server_id, name, category, weight, confidence, reasons) VALUES (?, ?, ?, ?, ?, ?)`,
			serverID, assessment.Tool, assessment.Category, assessment.Weight, assessment.Confidence, reasons,
		); err != nil {
			return err
		}
		for _, finding := range findings[assessment.Tool] {
			if _, err := tx.Exec(
				`INSERT INTO findings (server_id, tool_name, where_found, kind, severity, quote) VALUES (?, ?, ?, ?, ?, ?)`,
				serverID, assessment.Tool, finding.Where, finding.Kind, finding.Severity, finding.Quote,
			); err != nil {
				return err
			}
		}
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
		`SELECT tool_name, where_found, kind, severity, quote FROM findings WHERE server_id = ?`,
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
		if err := rows.Scan(&toolName, &finding.Where, &finding.Kind, &finding.Severity, &finding.Quote); err != nil {
			return nil, err
		}
		findings[toolName] = append(findings[toolName], finding)
	}
	return findings, rows.Err()
}