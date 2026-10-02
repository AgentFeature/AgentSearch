package hibp

import (
	"github.com/AgentFeature/agentsearch/internal/network"
	"testing"
	"time"
)

func TestRegressionClientKeyLifecycle(t *testing.T) {
	// Reuse the existing runtime-only test helper; no credential literals or network calls.
	key := testSecret(t)
	if _, err := NewClient("http://example.test/api/v3", key, network.NewServiceClient(time.Second)); err == nil {
		t.Fatal("insecure endpoint accepted")
	}
	if !key.Empty() {
		t.Error("failed constructor retained owned key")
		key.Destroy()
	}
	key = testSecret(t)
	client, err := NewClient("", key, network.NewServiceClient(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	closer, ok := any(client).(interface{ Close() })
	if !ok {
		t.Fatal("client cannot release its owned reusable credential")
	}
	closer.Close()
	closer.Close()
	if !key.Empty() {
		t.Fatal("closed client retained credential")
	}
}
