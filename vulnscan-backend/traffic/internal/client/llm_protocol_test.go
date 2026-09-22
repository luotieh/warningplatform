package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const completedResponse = `{"status":"completed","output":[{"type":"reasoning","summary":[{"text":"private reasoning"}]},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"最终回答"}]}]}`

func TestResponsesFallbackAcrossCallers(t *testing.T) {
	for _, kind := range []string{"report", "health", "healthTest"} {
		t.Run(kind, func(t *testing.T) {
			var calls []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls = append(calls, r.URL.Path)
				if r.Header.Get("Authorization") != "Bearer secret" {
					t.Error("authentication missing")
				}
				switch r.URL.Path {
				case "/v1/models":
					fmt.Fprint(w, `{"data":[]}`)
				case "/v1/chat/completions":
					w.WriteHeader(500)
					fmt.Fprint(w, `{"error":{"code":"convert_request_failed","message":"codex channel: /v1/chat/completions endpoint not supported"}}`)
				case "/v1/responses":
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					if body["stream"] != true || body["store"] != false || body["model"] != "configured-model" {
						t.Errorf("unexpected request: %v", body)
					}
					if _, ok := body["messages"]; ok {
						t.Error("chat messages leaked into Responses")
					}
					if _, ok := body["max_tokens"]; ok {
						t.Error("chat budget leaked into Responses")
					}
					budget := healthTestMaxTokens
					if kind == "report" {
						budget = ChatMaxTokens
						if body["instructions"] != "system rules" {
							t.Error("system prompt lost")
						}
						input := body["input"].([]any)[0].(map[string]any)
						content := input["content"].([]any)[0].(map[string]any)
						if input["role"] != "user" || content["text"] != "evidence" {
							t.Error("evidence lost")
						}
					}
					if body["max_output_tokens"] != float64(budget) {
						t.Errorf("budget=%v", body["max_output_tokens"])
					}
					w.Header().Set("Content-Type", "text/event-stream")
					fmt.Fprint(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n")
					fmt.Fprintf(w, "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":%s}\n\n", completedResponse)
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			c := LLMClient{BaseURL: srv.URL + "/v1", Model: "configured-model", APIKey: "secret"}
			switch kind {
			case "report":
				reply, err := c.Chat(context.Background(), "system rules", "evidence")
				if err != nil || reply != "最终回答" {
					t.Fatalf("reply=%q err=%v", reply, err)
				}
			case "health":
				h := c.HealthCheck(context.Background())
				if !h.OK || h.Endpoint != srv.URL+"/v1/responses" {
					t.Fatalf("%+v", h)
				}
			case "healthTest":
				h := c.HealthTest(context.Background())
				if !h.OK || h.Chat.Endpoint != srv.URL+"/v1/responses" || h.Chat.Reply != "最终回答" {
					t.Fatalf("%+v", h)
				}
			}
			if calls[len(calls)-2] != "/v1/chat/completions" || calls[len(calls)-1] != "/v1/responses" {
				t.Fatalf("calls=%v", calls)
			}
		})
	}
}

func TestExplicitResponsesJSONAndModelsPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			fmt.Fprint(w, `{"data":[]}`)
		case "/v1/responses":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, completedResponse)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	h := (LLMClient{BaseURL: srv.URL + "/v1/responses/", Model: "local"}).HealthTest(context.Background())
	if !h.OK || h.Connectivity.Endpoint != srv.URL+"/v1/models" {
		t.Fatalf("%+v", h)
	}
}

func TestNeverRetryAmbiguousFailures(t *testing.T) {
	for _, status := range []int{400, 401, 402, 403, 404, 429, 500, 502, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var n atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n.Add(1)
				w.WriteHeader(status)
				fmt.Fprint(w, `{"error":{"message":"unavailable"}}`)
			}))
			defer srv.Close()
			_, err := (LLMClient{BaseURL: srv.URL, Model: "k3"}).Chat(context.Background(), "s", "u")
			if err == nil || n.Load() != 1 {
				t.Fatalf("calls=%d err=%v", n.Load(), err)
			}
		})
	}
}

func TestRejectIncompleteResponses(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		stream     bool
	}{
		{"incomplete", `{"status":"incomplete","incomplete_details":{"reason":"max_output_tokens"},"output":[]}`, false},
		{"empty", `{"status":"completed","output":[]}`, false},
		{"refusal", `{"status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"refusal","refusal":"declined"}]}]}`, false},
		{"error", `{"error":{"message":"upstream failed"}}`, false},
		{"eof", "data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n", true},
		{"failed", "data: {\"type\":\"response.failed\",\"response\":{\"status\":\"failed\",\"error\":{\"message\":\"failed\"}}}\n\n", true},
		{"stream-error", "data: {\"type\":\"error\",\"message\":\"failed\"}\n\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.stream {
					w.Header().Set("Content-Type", "text/event-stream")
				}
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()
			reply, err := (LLMClient{BaseURL: srv.URL + "/responses"}).Chat(context.Background(), "s", "u")
			if err == nil || reply != "" {
				t.Fatalf("partial report accepted: reply=%q err=%v", reply, err)
			}
		})
	}
}

func TestReportRejectsTruncatedChat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"choices":[{"finish_reason":"length","message":{"content":"partial"}}]}`)
	}))
	defer srv.Close()
	reply, err := (LLMClient{BaseURL: srv.URL}).Chat(context.Background(), "s", "u")
	if err == nil || reply != "" {
		t.Fatalf("partial report accepted: reply=%q err=%v", reply, err)
	}
}

// DisableThinking 时 chat completions 请求必须带 enable_thinking=false，
// 避免思考链耗尽输出预算；未开启时不得携带该字段（兼容非 Qwen 服务）。
func TestChatDisableThinkingSendsTemplateKwargs(t *testing.T) {
	for _, disable := range []bool{true, false} {
		t.Run(fmt.Sprintf("disable=%v", disable), func(t *testing.T) {
			var captured map[string]any
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("decode request: %v", err)
				}
				captured = body
				fmt.Fprint(w, `{"choices":[{"finish_reason":"stop","message":{"content":"ok"}}]}`)
			}))
			defer srv.Close()
			c := LLMClient{BaseURL: srv.URL, Model: "qwen", DisableThinking: disable}
			if _, err := c.Chat(context.Background(), "s", "u"); err != nil {
				t.Fatalf("chat: %v", err)
			}
			kwargs, present := captured["chat_template_kwargs"].(map[string]any)
			if disable {
				if !present || kwargs["enable_thinking"] != false {
					t.Fatalf("missing enable_thinking=false: %v", captured)
				}
			} else if present {
				t.Fatalf("unexpected chat_template_kwargs: %v", captured)
			}
		})
	}
}

// 截断错误必须带上真实 completion_tokens，便于区分思考链耗尽与输出过长。
func TestChatTruncatedErrorIncludesUsage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"choices":[{"finish_reason":"length","message":{"content":"partial"}}],"usage":{"prompt_tokens":1234,"completion_tokens":6000,"total_tokens":7234}}`)
	}))
	defer srv.Close()
	_, err := (LLMClient{BaseURL: srv.URL}).Chat(context.Background(), "s", "u")
	if err == nil || !strings.Contains(err.Error(), "completion_tokens=6000") {
		t.Fatalf("err=%v", err)
	}
}

func TestResponsesCancellation(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, ": keepalive\n\n")
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
		close(canceled)
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := (LLMClient{BaseURL: srv.URL + "/responses", HTTP: &http.Client{Timeout: time.Second}}).Chat(ctx, "s", "u")
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "canceled") {
			t.Fatalf("%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("request did not stop")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("upstream connection not canceled")
	}
}
