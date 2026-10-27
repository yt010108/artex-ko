package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type planToken string

func (p planToken) Token(context.Context) (string, error) { return string(p), nil }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestChatGPTPlanTransport(t *testing.T) {
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("Authorization"); got != "Bearer renewed-token" {
			t.Fatalf("authorization = %q", got)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["store"] != false || body["stream"] != true {
			t.Fatalf("plan flags = %v/%v", body["store"], body["stream"])
		}
		if body["access_programs"].(map[string]any)["cyber"] != "standard" {
			t.Fatalf("Daybreak off must request standard: %#v", body["access_programs"])
		}
		if _, ok := body["temperature"]; ok {
			t.Fatal("temperature must be omitted")
		}
		if _, ok := body["max_output_tokens"]; ok {
			t.Fatal("max_output_tokens must be omitted")
		}
		tools := body["tools"].([]any)
		group := tools[0].(map[string]any)
		if len(tools) != 1 || group["type"] != "namespace" || group["name"] != "artex" {
			t.Fatalf("tools = %#v", tools)
		}
		input := body["input"].([]any)
		if input[0].(map[string]any)["namespace"] != "artex" {
			t.Fatalf("input = %#v", input)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok")), Header: make(http.Header)}, nil
	})
	raw := `{"model":"test","temperature":0.5,"max_output_tokens":100,"stream":false,"store":true,"tools":[{"type":"function","name":"run","parameters":{"type":"object"}}],"input":[{"type":"function_call","call_id":"1","name":"run","arguments":"{}"}]}`
	req, err := http.NewRequest(http.MethodPost, "https://api.openai.com/v1/responses", strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer placeholder")
	if _, err := (chatGPTPlanTransport{base: base, tokens: planToken("renewed-token")}).RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	wrong, _ := http.NewRequest(http.MethodPost, "https://example.com/v1/responses", strings.NewReader(raw))
	if _, err := (chatGPTPlanTransport{base: base, tokens: planToken("renewed-token")}).RoundTrip(wrong); err == nil {
		t.Fatal("unexpected host accepted")
	}
}

func TestChatGPTDaybreakBody(t *testing.T) {
	got, err := chatGPTPlanBody([]byte(`{"model":"gpt-6-sol","input":[{"role":"user","content":"test"}]}`), true)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		AccessPrograms struct {
			Cyber string `json:"cyber"`
		} `json:"access_programs"`
	}
	if err := json.Unmarshal(got, &body); err != nil || body.AccessPrograms.Cyber != "daybreak_blue" {
		t.Fatalf("Daybreak request = %s, err = %v", got, err)
	}
}

func TestChatGPTStreamRequiresCompletion(t *testing.T) {
	for _, tc := range []struct {
		name, stream string
		success      bool
	}{
		{"completed", "event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n", true},
		{"incomplete", "event: response.incomplete\ndata: {\"type\":\"response.incomplete\"}\n\n", false},
		{"failed", "event: response.failed\ndata: {\"type\":\"response.failed\",\"response\":{\"error\":{\"code\":\"subscription_sharing_usage_limit_exceeded\",\"message\":\"Limit reached\"}}}\n\n", false},
		{"truncated", "event: response.output_text.delta\ndata: {\"delta\":\"hello\"}\n\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &chatGPTStreamGuard{body: io.NopCloser(strings.NewReader(tc.stream))}
			_, err := io.ReadAll(body)
			if (err == nil) != tc.success {
				t.Fatalf("err = %v", err)
			}
			if tc.name == "failed" && !IsQuotaExhaustedMessage(err.Error()) {
				t.Fatalf("usage limit code missing from error: %v", err)
			}
		})
	}
}
