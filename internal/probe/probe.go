// Package probe asks a live MCP server what tools it exposes.
//
// The protocol side is deliberately minimal: initialise, announce, list tools, done. This is the
// smallest honest implementation of MCP's stdio transport - newline-delimited JSON-RPC 2.0 - and
// it exists so a scan can run against a real server instead of a saved file. Session recording,
// policy and replay are tapelog's job; this package only asks one question and writes nothing.
//
// The process is always started by the caller (a command and its arguments), and always killed when
// the listing is done or the context expires: a probe should never outlive the question it asked.
package probe

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"

	"github.com/Caseymccallum/slopscan/internal/risk"
)

// The MCP protocol version this speaks. Same era as tapelog's transport.
const protocolVersion = "2026-07-28"

// One JSON-RPC message, in the shape MCP's stdio transport uses.
type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Tools runs `command args...`, asks the server for its tool list, and returns it.
//
// The server gets no question beyond the protocol's own handshake: no tool is called, no resource
// is read. Whatever the listing says about itself is what comes back - which is exactly the input
// the classifier and the injection scanner want.
func Tools(ctx context.Context, command string, args ...string) ([]risk.Tool, error) {
	if command == "" {
		return nil, fmt.Errorf("no server command given")
	}

	process := exec.CommandContext(ctx, command, args...)
	stdin, err := process.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := process.StdoutPipe()
	if err != nil {
		return nil, err
	}
	// A server that logs to stderr would otherwise inherit ours and interleave with the report.
	process.Stderr = io.Discard

	if err := process.Start(); err != nil {
		return nil, fmt.Errorf("could not start %s: %w", command, err)
	}
	defer func() {
		_ = process.Process.Kill()
		_, _ = process.Process.Wait()
	}()

	reader := bufio.NewReader(stdout)
	writer := bufio.NewWriter(stdin)

	// The handshake: initialise, then the notification that says the client is ready. Both must
	// complete before tools/list or a strict server will refuse the question.
	if err := writeMessage(writer, message{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: mustJSON(map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "slopscan", "version": "0.1.0"},
		}),
	}); err != nil {
		return nil, err
	}

	initialized, err := readMessage(reader)
	if err != nil {
		return nil, fmt.Errorf("waiting for initialize: %w", err)
	}
	if initialized.Error != nil {
		return nil, fmt.Errorf("initialize refused: %s", initialized.Error.Message)
	}

	if err := writeMessage(writer, message{JSONRPC: "2.0", Method: "notifications/initialized"}); err != nil {
		return nil, err
	}
	if err := writeMessage(writer, message{JSONRPC: "2.0", ID: 2, Method: "tools/list"}); err != nil {
		return nil, err
	}

	for {
		reply, err := readMessage(reader)
		if err != nil {
			return nil, fmt.Errorf("waiting for tools/list: %w", err)
		}
		if reply.ID != 2 {
			continue // a notification or a late reply is not the answer to this question
		}
		if reply.Error != nil {
			return nil, fmt.Errorf("tools/list refused: %s", reply.Error.Message)
		}

		var result struct {
			Tools []risk.Tool `json:"tools"`
		}
		if err := json.Unmarshal(reply.Result, &result); err != nil {
			return nil, fmt.Errorf("tools/list sent something unreadable: %w", err)
		}
		return result.Tools, nil
	}
}

func writeMessage(writer *bufio.Writer, msg message) error {
	encoded, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if _, err := writer.Write(append(encoded, '\n')); err != nil {
		return err
	}
	return writer.Flush()
}

// readMessage reads one newline-delimited JSON-RPC message. Lines that are not JSON (a server's own
// stray output) are skipped rather than fatal: one bad line should not make a server unscannable.
func readMessage(reader *bufio.Reader) (message, error) {
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			var msg message
			if json.Unmarshal(line, &msg) == nil && (msg.ID != 0 || msg.Method != "") {
				return msg, nil
			}
		}
		if err != nil {
			return message{}, err
		}
	}
}

func mustJSON(value any) json.RawMessage {
	raw, _ := json.Marshal(value)
	return raw
}