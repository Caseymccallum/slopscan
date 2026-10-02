// Package probe asks a live MCP server what tools it exposes.
//
// The protocol side is deliberately minimal: initialise, announce, list tools, done. This is the
// smallest honest implementation of MCP's transports - stdio, streamable HTTP, and legacy
// HTTP+SSE - and it exists so a scan can run against a real server instead of a saved file.
// Session recording, policy and replay are tapelog's job; this package only asks one question
// and writes nothing.
//
// A stdio process is always started by the caller (a command and its arguments), and always
// killed when the listing is done or the context expires; a remote endpoint is asked over HTTP
// and forgotten. A probe should never outlive the question it asked.
package probe

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
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
	return ToolsIn(ctx, nil, command, args...)
}

// ToolsIn is Tools with the environment a client configuration declares - the same env the agent
// would launch the server with, so the listing comes from the server as it really runs.
func ToolsIn(ctx context.Context, env map[string]string, command string, args ...string) ([]risk.Tool, error) {
	if command == "" {
		return nil, fmt.Errorf("no server command given")
	}

	process := exec.CommandContext(ctx, command, args...)
	if len(env) > 0 {
		// Seeded from the parent environment: replacing it outright would leave the server
		// without PATH and everything else it needs to start.
		process.Env = os.Environ()
		for key, value := range env {
			process.Env = append(process.Env, key+"="+value)
		}
	}
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

	// The handshake, then every listing surface the server offers. The listings are the whole
	// question: what the server says about itself. Nothing on it is ever acted on.
	return listAll(ctx, &stdioTransport{writer: writer, reader: reader})
}

// stdioTransport carries a call over the newline stream: write the message, wait for the reply
// that carries its id. A notification or a late reply is not the answer to this question.
type stdioTransport struct {
	writer *bufio.Writer
	reader *bufio.Reader
}

func (t *stdioTransport) call(ctx context.Context, msg message) (message, error) {
	if err := writeMessage(t.writer, msg); err != nil {
		return message{}, err
	}
	for {
		reply, err := readMessage(t.reader)
		if err != nil {
			return message{}, fmt.Errorf("waiting for %s: %w", msg.Method, err)
		}
		if reply.ID == msg.ID {
			return reply, nil
		}
	}
}

func (t *stdioTransport) notify(ctx context.Context, msg message) error {
	return writeMessage(t.writer, msg)
}

// The handshake every transport speaks, in one place: initialize, the ready notification, and
// the listings. A stdio line and an HTTP POST carry the same bytes.
func initializeRequest() message {
	return message{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: mustJSON(map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "slopscan", "version": "0.1.0"},
		}),
	}
}

func initializedNotification() message {
	return message{JSONRPC: "2.0", Method: "notifications/initialized"}
}

// listPage is the shape all four listing replies share: a nextCursor and one populated array.
type listPage struct {
	Tools      []risk.Tool   `json:"tools"`
	Prompts    []promptDef   `json:"prompts"`
	Resources  []resourceDef `json:"resources"`
	Templates  []resourceDef `json:"resourceTemplates"`
	NextCursor string        `json:"nextCursor"`
}

// promptDef is a prompt as a server describes it: a name, a description, and arguments whose
// descriptions reach the model too - so they are carried into the schema the scanner reads.
type promptDef struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Arguments   []promptArgs `json:"arguments"`
}

type promptArgs struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// resourceDef is a resource or resource template: named text at an address. The address is
// identity - it travels with the definition so a moved resource is a noticed change.
type resourceDef struct {
	URI         string `json:"uri"`
	URITemplate string `json:"uriTemplate"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// listAll runs the handshake and reads every listing surface: the three things a server says
// about itself. Tools are the question the probe requires; prompts and resources are offered -
// a server that refuses them exposes none the agent could see either.
func listAll(ctx context.Context, t transport) ([]risk.Tool, error) {
	initialized, err := t.call(ctx, initializeRequest())
	if err != nil {
		return nil, fmt.Errorf("waiting for initialize: %w", err)
	}
	if initialized.Error != nil {
		return nil, fmt.Errorf("initialize refused: %s", initialized.Error.Message)
	}
	if err := t.notify(ctx, initializedNotification()); err != nil {
		return nil, err
	}

	entries := []risk.Tool{}
	nextID := 2
	for _, listing := range []struct {
		method   string
		surface  string
		required bool
	}{
		{"tools/list", "", true},
		{"prompts/list", "prompt", false},
		{"resources/list", "resource", false},
		{"resources/templates/list", "resource", false},
	} {
		found, err := listSurface(ctx, t, listing.method, listing.surface, listing.required, &nextID)
		if err != nil {
			return nil, err
		}
		entries = append(entries, found...)
	}
	return entries, nil
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

// listSurface reads one listing, following nextCursor to the end - a rug pull must not be able
// to hide on page 2 of the very listing the probe is pinning.
func listSurface(ctx context.Context, t transport, method, surface string, required bool, nextID *int) ([]risk.Tool, error) {
	entries := []risk.Tool{}
	cursor := ""
	for {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		id := *nextID
		*nextID = *nextID + 1

		reply, err := t.call(ctx, message{JSONRPC: "2.0", ID: id, Method: method, Params: mustJSON(params)})
		if err != nil || reply.Error != nil {
			if required {
				if err != nil {
					return nil, fmt.Errorf("waiting for %s: %w", method, err)
				}
				return nil, fmt.Errorf("%s refused: %s", method, reply.Error.Message)
			}
			// An optional surface that will not answer is absent to the agent too: a client
			// that cannot list a prompt never loads it into anyone's context.
			return nil, nil
		}

		var page listPage
		if err := json.Unmarshal(reply.Result, &page); err != nil {
			if required {
				return nil, fmt.Errorf("%s sent something unreadable: %w", method, err)
			}
			return nil, nil
		}
		entries = append(entries, page.entries(surface)...)
		if page.NextCursor == "" {
			return entries, nil
		}
		cursor = page.NextCursor
	}
}

// entries flattens whichever array the reply carried, mapped onto the common definition.
func (p listPage) entries(surface string) []risk.Tool {
	out := []risk.Tool{}
	for _, tool := range p.Tools {
		out = append(out, tool)
	}
	for _, prompt := range p.Prompts {
		properties := map[string]any{}
		for _, arg := range prompt.Arguments {
			properties[arg.Name] = map[string]any{"type": "string", "description": arg.Description}
		}
		entry := risk.Tool{Name: prompt.Name, Description: prompt.Description, Surface: surface}
		if len(properties) > 0 {
			entry.InputSchema = map[string]any{"type": "object", "properties": properties}
		}
		out = append(out, entry)
	}
	for _, resource := range p.Resources {
		out = append(out, risk.Tool{Name: resource.Name, Description: resource.Description, Surface: surface, URI: resource.URI})
	}
	for _, template := range p.Templates {
		out = append(out, risk.Tool{Name: template.Name, Description: template.Description, Surface: surface, URI: template.URITemplate})
	}
	return out
}