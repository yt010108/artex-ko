package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ChatGPTTokenSource supplies a refreshed token for the ChatGPT plan route.
// The token never enters an LLM profile or the browser.
type ChatGPTTokenSource interface {
	Token(context.Context) (string, error)
}

type chatGPTPlanTransport struct {
	base     http.RoundTripper
	tokens   ChatGPTTokenSource
	daybreak bool
}

func (t chatGPTPlanTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodPost || req.URL.Scheme != "https" || req.URL.Host != "api.openai.com" || req.URL.Path != "/v1/responses" {
		return nil, fmt.Errorf("ChatGPT 플랜 요청은 OpenAI Responses API로만 보낼 수 있습니다")
	}
	token, err := t.tokens.Token(req.Context())
	if err != nil {
		return nil, err
	}
	const maxBody = 32 << 20
	raw, err := io.ReadAll(io.LimitReader(req.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxBody {
		return nil, fmt.Errorf("ChatGPT 요청 본문이 너무 큽니다")
	}
	body, err := chatGPTPlanBody(raw, t.daybreak)
	if err != nil {
		return nil, err
	}
	copyReq := req.Clone(req.Context())
	copyReq.Header = req.Header.Clone()
	copyReq.Header.Set("Authorization", "Bearer "+token)
	copyReq.Body = io.NopCloser(bytes.NewReader(body))
	copyReq.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	copyReq.ContentLength = int64(len(body))
	resp, err := t.base.RoundTrip(copyReq)
	if err == nil && resp != nil && resp.StatusCode == http.StatusOK {
		resp.Body = &chatGPTStreamGuard{body: resp.Body}
	}
	return resp, err
}

// ChatGPT plan inference only succeeds after response.completed. Norma accepts
// response.incomplete as a terminal message, so reject it at the wire boundary.
type chatGPTStreamGuard struct {
	body      io.ReadCloser
	line      []byte
	completed bool
}

func (g *chatGPTStreamGuard) Read(p []byte) (int, error) {
	n, err := g.body.Read(p)
	for _, b := range p[:n] {
		if b != '\n' {
			if len(g.line) < 1<<20 {
				g.line = append(g.line, b)
			}
			continue
		}
		line := strings.TrimSpace(string(g.line))
		g.line = g.line[:0]
		if line == "event: response.completed" {
			g.completed = true
		}
		if line == "event: response.incomplete" {
			return 0, fmt.Errorf("ChatGPT 응답이 완료되지 않았습니다")
		}
		if strings.HasPrefix(line, "data:") {
			var frame struct {
				Type     string `json:"type"`
				Response struct {
					Error struct {
						Code    string `json:"code"`
						Message string `json:"message"`
					} `json:"error"`
				} `json:"response"`
			}
			if json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "data:"))), &frame) == nil {
				if frame.Type == "response.completed" {
					g.completed = true
				}
				if frame.Type == "response.incomplete" {
					return 0, fmt.Errorf("ChatGPT 응답이 완료되지 않았습니다")
				}
				if frame.Type == "response.failed" {
					return 0, fmt.Errorf("ChatGPT 응답 실패: %s %s", frame.Response.Error.Code, frame.Response.Error.Message)
				}
			}
		}
	}
	if err == io.EOF && !g.completed {
		return n, fmt.Errorf("ChatGPT 응답 완료 이벤트가 없습니다")
	}
	return n, err
}

func (g *chatGPTStreamGuard) Close() error { return g.body.Close() }

// Norma already sends full history, instructions and store:false. The ChatGPT
// plan route additionally requires streaming, omits several API-key-only fields,
// and accepts local function tools grouped in a namespace.
func chatGPTPlanBody(raw []byte, daybreak bool) ([]byte, error) {
	var body map[string]json.RawMessage
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("ChatGPT 요청 본문 오류: %w", err)
	}
	if body == nil {
		return nil, fmt.Errorf("ChatGPT 요청 본문이 비어 있습니다")
	}
	for _, key := range []string{"background", "conversation", "max_output_tokens", "max_tool_calls", "metadata", "moderation", "multi_agent", "prompt", "prompt_cache_retention", "safety_identifier", "temperature", "top_logprobs", "top_p", "truncation", "user", "previous_response_id"} {
		delete(body, key)
	}
	body["store"] = json.RawMessage("false")
	body["stream"] = json.RawMessage("true")
	// Explicit standard keeps the switch off even for approved accounts whose
	// selected model would otherwise default to a Daybreak program.
	if daybreak {
		body["access_programs"] = json.RawMessage(`{"cyber":"daybreak_blue"}`)
	} else {
		body["access_programs"] = json.RawMessage(`{"cyber":"standard"}`)
	}
	if rawTools := body["tools"]; len(rawTools) > 0 {
		var tools []json.RawMessage
		if err := json.Unmarshal(rawTools, &tools); err != nil {
			return nil, fmt.Errorf("ChatGPT 도구 정의 오류: %w", err)
		}
		if len(tools) > 0 {
			group, err := json.Marshal(map[string]any{
				"type": "namespace", "name": "artex", "description": "ARTEX local tools", "tools": tools,
			})
			if err != nil {
				return nil, err
			}
			body["tools"] = json.RawMessage("[" + string(group) + "]")
		}
	}
	if rawInput := body["input"]; len(rawInput) > 0 {
		var input []map[string]json.RawMessage
		if err := json.Unmarshal(rawInput, &input); err != nil {
			return nil, fmt.Errorf("ChatGPT 대화 기록 오류: %w", err)
		}
		for _, item := range input {
			if string(item["type"]) == `"function_call"` || string(item["type"]) == `"function_call_output"` {
				item["namespace"] = json.RawMessage(`"artex"`)
			}
		}
		encoded, err := json.Marshal(input)
		if err != nil {
			return nil, err
		}
		body["input"] = encoded
	}
	return json.Marshal(body)
}
