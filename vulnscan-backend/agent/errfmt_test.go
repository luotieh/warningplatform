package agent

import "testing"

func TestFormatHTTPErrorBody_HTML(t *testing.T) {
	body := []byte("<!DOCTYPE html><html><title>404</title></html>")
	got := FormatHTTPErrorBody(body)
	if got == string(body) {
		t.Fatalf("expected sanitized message, got raw html")
	}
}

func TestFormatErrorDetail_TruncatesLongMessage(t *testing.T) {
	err := fmtError("HTTP 404: " + string(make([]byte, 500)))
	got := FormatErrorDetail(err)
	if len(got) > 250 {
		t.Fatalf("expected truncation, len=%d", len(got))
	}
}

type fmtError string

func (e fmtError) Error() string { return string(e) }
