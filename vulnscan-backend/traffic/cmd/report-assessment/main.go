// report-assessment consumes frozen outputs; it has no database or evidence
// executor entry point. API credentials are read only from process environment.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vulnscan-backend/traffic/internal/client"
	"vulnscan-backend/traffic/internal/service"
)

func read(path string, value any) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, value)
}
func write(path string, value any) error {
	b, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	if key := os.Getenv("K27_API_KEY"); key != "" {
		b = []byte(strings.ReplaceAll(string(b), key, "[REDACTED]"))
	}
	return os.WriteFile(path, append(b, '\n'), 0600)
}
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	source := flag.String("source", "", "immutable scenario directory")
	out := flag.String("out", "", "assessment output directory")
	mode := flag.String("mode", "prepare", "prepare, call or validate")
	allowHTTP := flag.Bool("allow-configured-http", false, "explicit human-authorized override for the existing server model HTTP route")
	serverModel := flag.Bool("use-existing-server-model", false, "use the existing authorized server model and key; rotation is not independently asserted")
	flag.Parse()
	var bundle service.PreparedEvidenceBundle
	var frozen service.PreparedEvidenceExecution
	if e := read(filepath.Join(*source, "prepared-bundle.json"), &bundle); e != nil {
		return e
	}
	if e := bundle.Validate(); e != nil {
		return e
	}
	if e := read(filepath.Join(*source, "normalized-result.json"), &frozen); e != nil {
		return e
	}
	contextBytes, e := os.ReadFile(filepath.Join(*out, "assessment-context.json"))
	if e != nil {
		return e
	}
	request, e := service.PrepareOfflineReport(bundle.Event, frozen, contextBytes)
	if e != nil {
		return e
	}
	inputHash := digest(request.User)
	base, model := os.Getenv("K27_BASE_URL"), os.Getenv("K27_MODEL")
	if *mode == "prepare" {
		if e = write(filepath.Join(*out, "llm-input.json"), json.RawMessage(request.User)); e != nil {
			return e
		}
		var previous struct {
			Status string `json:"status"`
			Hash   string `json:"input_sha256"`
		}
		if read(filepath.Join(*out, "llm-request-redacted.json"), &previous) == nil && previous.Status == "dispatched" {
			if previous.Hash != inputHash {
				return fmt.Errorf("existing_request_input_changed_archive_before_new_generation")
			}
			return nil // Never replace a real request audit during zero-cost replay.
		}
		return write(filepath.Join(*out, "llm-request-redacted.json"), map[string]any{"status": "prepared_not_sent", "sent": false, "model": model, "base_url": base, "prompt_version": request.PromptVersion, "input_sha256": inputHash, "system": request.System, "user": json.RawMessage(request.User), "max_output_tokens": 6000, "max_generation_calls": 2, "transport_attempts_per_generation_max": 2})
	}
	responsePath := filepath.Join(*out, "llm-response.json")
	if *mode == "call" {
		// HTTP remains forbidden by default. This task's human explicitly allowed
		// the existing 180 server HTTP configuration; never infer that override.
		key := os.Getenv("K27_API_KEY")
		u, parseErr := url.Parse(base)
		if parseErr != nil || (u.Scheme != "https" && !(u.Scheme == "http" && *allowHTTP && *serverModel)) || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("K27_BASE_URL_requires_confirmed_https_api_route")
		}
		if key == "" || model == "" || (os.Getenv("K27_KEY_ROTATED") != "1" && !*serverModel) {
			return fmt.Errorf("rotated_key_and_confirmed_model_required; set K27_KEY_ROTATED=1 after rotation")
		}
		// Preserve any previous paid response; reruns require explicit archival.
		if _, err := os.Stat(responsePath); err == nil {
			var old struct {
				Real bool `json:"real_api_executed"`
			}
			_ = read(responsePath, &old)
			if old.Real {
				return fmt.Errorf("existing_real_response_use_ReuseResponse_or_archive_explicitly")
			}
		}
		jar, _ := cookiejar.New(nil)
		h := &http.Client{Timeout: 180 * time.Second, Jar: jar, CheckRedirect: func(next *http.Request, via []*http.Request) error {
			// A same-origin GET validation redirect can establish the provider's
			// session cookie. Never forward credentials to another origin or
			// allow a report POST to turn into a GET or be resent automatically.
			if len(via) > 3 || len(via) == 0 || via[0].Method != http.MethodGet || next.URL.Host != u.Host || next.URL.Scheme != u.Scheme {
				return http.ErrUseLastResponse
			}
			return nil
		}}
		c := client.LLMClient{BaseURL: base, APIKey: key, Model: model, MaxTokens: 6000, HTTP: h}
		// Check the configured service contract and exact model before paid calls.
		modelBase := strings.TrimRight(base, "/")
		for _, suffix := range []string{"/chat/completions", "/responses"} {
			modelBase = strings.TrimSuffix(modelBase, suffix)
		}
		req, err := http.NewRequest(http.MethodGet, modelBase+"/models", nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+key)
		resp, err := h.Do(req)
		if err != nil {
			return fmt.Errorf("secure_model_discovery_failed")
		}
		var listing struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		err = json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 2<<20)).Decode(&listing)
		resp.Body.Close()
		found := false
		for _, item := range listing.Data {
			if item.ID == model {
				found = true
			}
		}
		if e = write(filepath.Join(*out, "model-compatibility.json"), map[string]any{"http_status": resp.StatusCode, "configured_model": model, "model_id_in_list": found, "json_parsed": err == nil, "same_origin_get_redirects_max": 3, "post_redirects_disabled": true}); e != nil {
			return e
		}
		if err != nil || resp.StatusCode != 200 || !found {
			// A configured exact model may be absent from an unsupported /models
			// route. Do not bypass authentication/quota errors or guess an alias.
			if !(*serverModel && model == "K2.7" && (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusOK)) {
				return fmt.Errorf("configured_model_not_confirmed_by_provider_models")
			}
		}
		calls, dispatches := 0, 0
		for attempt := 1; attempt <= 2; attempt++ {
			prompt := string(request.User)
			if attempt == 2 {
				var prior map[string]any
				_ = read(filepath.Join(*out, "llm-response-01.json"), &prior)
				var validation map[string]any
				_ = read(filepath.Join(*out, "report-validation.json"), &validation)
				fix := map[string]any{"original_input": json.RawMessage(request.User), "previous_reply": prior["reply"], "validation_failure": validation, "repair": "保持证据、来源和分数不变，修正校验错误，仅返回正式ReportAssessment JSON"}
				b, _ := json.Marshal(fix)
				if len(b) > 100000 {
					return fmt.Errorf("repair_budget_exceeded")
				}
				prompt = string(b)
			}
			observed := []map[string]any{}
			c.ReportObserver = func(stage string, v any) {
				if stage == "dispatch" {
					dispatches++
				}
				observed = append(observed, map[string]any{"stage": stage, "data": v})
			}
			start := time.Now()
			calls++
			reply, callErr := c.Chat(context.Background(), request.System, prompt)
			requestRecord := map[string]any{"status": "dispatched", "model": model, "prompt_version": request.PromptVersion, "input_sha256": inputHash, "prompt_sha256": digest([]byte(prompt)), "system": request.System, "user": json.RawMessage(prompt), "audit": observed, "api_generation_calls": calls, "http_dispatches": dispatches, "http_override_explicitly_authorized": *allowHTTP, "existing_server_model_authorized": *serverModel, "model_discovery_status": resp.StatusCode, "model_list_contains_configured_id": found}
			if e = write(filepath.Join(*out, fmt.Sprintf("llm-request-%02d-redacted.json", attempt)), requestRecord); e != nil {
				return e
			}
			if attempt == 1 {
				if e = write(filepath.Join(*out, "llm-request-redacted.json"), requestRecord); e != nil {
					return e
				}
			}
			// Error strings and provider bodies are not archived: they may echo auth.
			result := map[string]any{"model": model, "input_sha256": inputHash, "real_api_executed": dispatches > 0, "api_generation_calls": calls, "http_dispatches": dispatches, "elapsed_ms": time.Since(start).Milliseconds(), "reply": reply, "audit": observed, "status": "response_received"}
			result["model_response_received"] = callErr == nil && reply != ""
			result["provider_request_id"] = nil // Not exposed by the existing protocol observer.
			for _, event := range observed {
				if event["stage"] == "response" {
					if data, ok := event["data"].(map[string]any); ok {
						result["usage"] = data["usage"]
					}
				}
			}
			if callErr != nil {
				result["status"] = "api_failed"
				result["error"] = "provider_or_transport_failure_see_sanitized_audit"
			}
			// Scrub key even if a provider echoes it in a reply or diagnostic.
			b, _ := json.Marshal(result)
			b = []byte(strings.ReplaceAll(string(b), key, "[REDACTED]"))
			if e = write(responsePath, json.RawMessage(b)); e != nil {
				return e
			}
			if e = write(filepath.Join(*out, fmt.Sprintf("llm-response-%02d.json", attempt)), json.RawMessage(b)); e != nil {
				return e
			}
			if callErr != nil {
				return fmt.Errorf("real_model_call_failed_no_automatic_retry")
			}
			e = validate(*out, bundle, frozen, model, inputHash, reply)
			if validation, readErr := os.ReadFile(filepath.Join(*out, "report-validation.json")); readErr == nil {
				if writeErr := write(filepath.Join(*out, fmt.Sprintf("report-validation-%02d.json", attempt)), json.RawMessage(validation)); writeErr != nil {
					return writeErr
				}
			}
			if attempt == 2 {
				var prior map[string]any
				_ = read(filepath.Join(*out, "llm-response-01.json"), &prior)
				if writeErr := write(filepath.Join(*out, "report-repair-comparison.json"), map[string]any{"original_reply": prior["reply"], "repaired_reply": reply, "changed": prior["reply"] != reply, "passed": e == nil, "original_validation": "report-validation-01.json", "repaired_validation": "report-validation-02.json"}); writeErr != nil {
					return writeErr
				}
			}
			if e == nil {
				return nil
			}
		}
		return fmt.Errorf("report_failed_after_one_bounded_repair")
	}
	if *mode != "validate" {
		return fmt.Errorf("unknown_mode")
	}
	var saved struct {
		Real   bool   `json:"real_api_executed"`
		Hash   string `json:"input_sha256"`
		Model  string `json:"model"`
		Reply  string `json:"reply"`
		Status string `json:"status"`
	}
	if e = read(responsePath, &saved); e != nil {
		return e
	}
	if !saved.Real || saved.Status != "response_received" || saved.Hash != inputHash {
		return fmt.Errorf("no_matching_real_model_response")
	}
	return validate(*out, bundle, frozen, saved.Model, inputHash, saved.Reply)
}
func validate(out string, b service.PreparedEvidenceBundle, f service.PreparedEvidenceExecution, model, hash, reply string) error {
	if key := os.Getenv("K27_API_KEY"); key != "" && strings.Contains(reply, key) {
		return fmt.Errorf("provider_reply_contained_secret_rejected")
	}
	doc, e := service.ValidateOfflineReport(reply, b.Event, f, model)
	result := map[string]any{"passed": e == nil, "status": "validated", "validator": "production decodeReportAssessment + offline provenance disclosure", "input_sha256": hash, "human_review": "pending; structure/reference/numeric checks do not establish semantic quality"}
	if e != nil {
		result["status"] = "failed"
		result["error"] = e.Error()
	}
	if err := write(filepath.Join(out, "report-validation.json"), result); err != nil {
		return err
	}
	if e != nil {
		return e
	}
	doc = service.RenderOfflineReportDocument(doc, b)
	if e = write(filepath.Join(out, "report-document.json"), doc); e != nil {
		return e
	}
	return os.WriteFile(filepath.Join(out, "final-report.md"), []byte(doc.Markdown), 0600)
}
