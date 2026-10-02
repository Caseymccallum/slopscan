package probe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Caseymccallum/slopscan/internal/risk"
)

// The remote transports: streamable HTTP (one POST per message, an answer as JSON or as an SSE
// stream) and legacy HTTP+SSE (a GET stream that names the POST endpoint, answers riding back on
// the stream). Same handshake as stdio - initialize, announce, tools/list - because MCP is one
// protocol and a probe that only spoke stdio was leaving every remote entry unasked. Session
// headers are honoured (`Mcp-Session-Id`, `MCP-Protocol-Version`); auth headers come from the
// client configuration and travel on every request.

// transport carries the handshake: one call that expects an answer, one notification that does
// not. stdio, streamable HTTP and HTTP+SSE all implement it - one sequence, three wires.
type transport interface {
	call(ctx context.Context, msg message) (message, error)
	notify(ctx context.Context, msg message) error
}

// ToolsURL asks a remote MCP server for its tool list over streamable HTTP, falling back to
// legacy HTTP+SSE when the endpoint refuses POSTs (the 2024-11-05 transport still deployed).
// The server is asked one question and nothing else: no tool is called, no resource is read.
func ToolsURL(ctx context.Context, endpoint string, headers map[string]string) ([]risk.Tool, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("no server URL given")
	}
	// A probe should never outlive the question it asked - a streamable endpoint that never
	// answers must not hang the run past its own deadline.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	client := &http.Client{}
	streamable := &httpTransport{url: endpoint, headers: headers, client: client}

	reply, err := streamable.call(ctx, initializeRequest())
	switch {
	case err == nil:
		if reply.Error != nil {
			return nil, fmt.Errorf("initialize refused: %s", reply.Error.Message)
		}
		if err := streamable.notify(ctx, initializedNotification()); err != nil {
			return nil, err
		}
		tools, err := streamable.call(ctx, toolsListRequest())
		if err != nil {
			return nil, fmt.Errorf("waiting for tools/list: %w", err)
		}
		return decodeTools(tools)
	case isLegacyRefusal(err):
		// The endpoint refuses POSTs: this is the older transport, where the stream comes
		// first and names where to post.
		return toolsFromLegacySSE(ctx, endpoint, headers, client)
	default:
		return nil, err
	}
}

// isLegacyRefusal reports whether a failed first call means "try the legacy transport" rather
// than "this server is broken": an endpoint that only speaks HTTP+SSE rejects POSTs outright.
func isLegacyRefusal(err error) bool {
	if err == nil {
		return false
	}
	text := err.Error()
	return strings.Contains(text, "answered 405") || strings.Contains(text, "answered 404")
}

// httpTransport is one endpoint to POST messages to - the URL itself for streamable HTTP, or the
// POST URL an HTTP+SSE stream named.
type httpTransport struct {
	url     string
	headers map[string]string
	client  *http.Client
	session string
}

func (t *httpTransport) call(ctx context.Context, msg message) (message, error) {
	resp, err := t.post(ctx, msg)
	if err != nil {
		return message{}, err
	}
	defer resp.Body.Close()
	t.captureSession(resp)

	switch {
	case resp.StatusCode == http.StatusAccepted:
		return message{}, fmt.Errorf("endpoint accepted the request without answering it")
	case resp.StatusCode != http.StatusOK:
		return message{}, fmt.Errorf("endpoint answered %d", resp.StatusCode)
	}

	// The answer is either one JSON document or an SSE stream carrying it among events.
	if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		return waitFor(ctx, streamSSE(ctx, resp.Body), msg.ID)
	}
	var reply message
	if err := json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return message{}, fmt.Errorf("endpoint sent something unreadable: %w", err)
	}
	return reply, nil
}

func (t *httpTransport) notify(ctx context.Context, msg message) error {
	resp, err := t.post(ctx, msg)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	t.captureSession(resp)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("endpoint answered %d to a notification", resp.StatusCode)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func (t *httpTransport) post(ctx context.Context, msg message) (*http.Response, error) {
	raw, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if t.session != "" {
		req.Header.Set("Mcp-Session-Id", t.session)
		req.Header.Set("MCP-Protocol-Version", protocolVersion)
	}
	// The configuration's headers last: they carry the credentials and win any conflict.
	for key, value := range t.headers {
		req.Header.Set(key, value)
	}
	return t.client.Do(req)
}

func (t *httpTransport) captureSession(resp *http.Response) {
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		t.session = sid
	}
}

// toolsFromLegacySSE speaks the 2024-11-05 transport: open the stream first, let it name the POST
// endpoint, then carry the same handshake over it. The answers ride the stream back.
func toolsFromLegacySSE(ctx context.Context, endpoint string, headers map[string]string, client *http.Client) ([]risk.Tool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/event-stream")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("opening the stream: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("stream endpoint answered %d", resp.StatusCode)
	}

	events := streamSSE(ctx, resp.Body)
	postURL := ""
	for postURL == "" {
		event, ok := <-events
		if !ok {
			return nil, fmt.Errorf("stream ended without naming a POST endpoint")
		}
		if event.name == "endpoint" {
			postURL = resolveURL(endpoint, strings.TrimSpace(event.data))
		}
	}

	legacy := &httpTransport{url: postURL, headers: headers, client: client}
	initialized, err := legacy.callOn(ctx, events, initializeRequest())
	if err != nil {
		return nil, fmt.Errorf("waiting for initialize: %w", err)
	}
	if initialized.Error != nil {
		return nil, fmt.Errorf("initialize refused: %s", initialized.Error.Message)
	}
	if err := legacy.notify(ctx, initializedNotification()); err != nil {
		return nil, err
	}
	reply, err := legacy.callOn(ctx, events, toolsListRequest())
	if err != nil {
		return nil, fmt.Errorf("waiting for tools/list: %w", err)
	}
	return decodeTools(reply)
}

// callOn posts a request and waits for its answer on an open stream - the legacy transport's
// shape, where the POST is fire-and-forget and the stream carries the reply.
func (t *httpTransport) callOn(ctx context.Context, events <-chan sseEvent, msg message) (message, error) {
	if _, err := t.post(ctx, msg); err != nil {
		return message{}, err
	}
	return waitFor(ctx, events, msg.ID)
}

// resolveURL turns the stream's endpoint notice into a postable URL: relative in every real
// deployment seen, absolute allowed by the spec.
func resolveURL(base, named string) string {
	ref, err := url.Parse(named)
	if err != nil {
		return named
	}
	parsed, err := url.Parse(base)
	if err != nil {
		return named
	}
	return parsed.ResolveReference(ref).String()
}

// sseEvent is one server-sent event: its name (empty when the server sends none) and its data.
type sseEvent struct {
	name string
	data string
}

// streamSSE reads a body as server-sent events until EOF or cancellation. A blank line ends an
// event; data lines join with newlines, per the wire format - no buffering tricks, because an
// event stream is already the framing.
func streamSSE(ctx context.Context, body io.Reader) <-chan sseEvent {
	events := make(chan sseEvent)
	go func() {
		defer close(events)
		scanner := newSSEScanner(body)
		name := ""
		data := []string{}
		emit := func() {
			if name == "" && len(data) == 0 {
				return
			}
			event := sseEvent{name: name, data: strings.Join(data, "\n")}
			name, data = "", []string{}
			select {
			case events <- event:
			case <-ctx.Done():
			}
		}
		for scanner.Scan() {
			line := scanner.Text()
			switch {
			case line == "":
				emit()
			case strings.HasPrefix(line, "data:"):
				data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
			case strings.HasPrefix(line, "event:"):
				name = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			}
			// Anything else (id, retry, comments) is not ours to interpret.
		}
		emit()
	}()
	return events
}

// waitFor reads events until the answer to a specific request arrives - a stream may carry
// notifications and other traffic first, and only the matching id is the question's answer.
func waitFor(ctx context.Context, events <-chan sseEvent, id int) (message, error) {
	for {
		select {
		case <-ctx.Done():
			return message{}, ctx.Err()
		case event, ok := <-events:
			if !ok {
				return message{}, fmt.Errorf("stream ended before the answer arrived")
			}
			var msg message
			if json.Unmarshal([]byte(event.data), &msg) == nil && msg.ID == id {
				return msg, nil
			}
		}
	}
}

// newSSEScanner reads lines with room for large events: a tool list can be big, and a scanner
// that gave up at its default limit would call a working server broken.
func newSSEScanner(body io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	return scanner
}