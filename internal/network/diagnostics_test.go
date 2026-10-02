package network

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/go-retryablehttp"
)

func TestRetryDiagnosticsOmitRequestAndError(t *testing.T) {
	var b bytes.Buffer
	original := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&b, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(original)
	client := NewRetryableClient(&http.Client{}, 1)
	retry := client.Transport.(*retryablehttp.RoundTripper).Client
	request, _ := http.NewRequest("GET", "https://private-user:private-password@example.test/private-email@example.test?key=private-key", nil)
	response := &http.Response{StatusCode: 429, Request: request}
	again, err := retry.CheckRetry(context.Background(), response, errors.New("private-upstream-body"))
	if !again || err != nil {
		t.Fatal("retry policy changed")
	}
	if b.Len() > 512 || strings.Contains(b.String(), "private-") || !strings.Contains(b.String(), `"status":429`) {
		t.Fatal("unsafe retry diagnostics")
	}
}
