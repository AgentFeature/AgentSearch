package websites

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/network"
)

// countingTransport measures exactly how many response-body bytes the
// website pipeline reads from the wire.
type countingTransport struct {
	inner http.RoundTripper
	bytes *atomic.Int64
}

type countingBody struct {
	io.ReadCloser
	bytes *atomic.Int64
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.bytes.Add(int64(n))
	return n, err
}

func (t *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.inner.RoundTrip(req)
	if resp != nil && resp.Body != nil {
		resp.Body = &countingBody{ReadCloser: resp.Body, bytes: t.bytes}
	}
	return resp, err
}

// perfFixture builds a deterministic offline provider mix:
// status_code sites with large bodies, message sites with markers, and a
// group of identical requests. It reports request count, body bytes read
// and wall-clock duration for one full username search.
func perfFixture(t *testing.T) (sites []models.SiteConfig, server *httptest.Server, requests *atomic.Int64) {
	t.Helper()
	requests = &atomic.Int64{}
	big := strings.Repeat("x", 96*1024)
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch {
		case strings.HasPrefix(r.URL.Path, "/status/found/"):
			io.WriteString(w, "<html>"+big+"</html>")
		case strings.HasPrefix(r.URL.Path, "/status/absent/"):
			w.WriteHeader(404)
			io.WriteString(w, "<html>"+big+"</html>")
		case strings.HasPrefix(r.URL.Path, "/msg/found/"):
			io.WriteString(w, "<html><div class=\"profile-marker\">user</div>"+big[:8*1024]+"</html>")
		case strings.HasPrefix(r.URL.Path, "/msg/absent/"):
			io.WriteString(w, "<html>profile does not exist</html>")
		default:
			io.WriteString(w, "<html>shared endpoint"+big[:4*1024]+"</html>")
		}
	}))
	for i := 0; i < 15; i++ {
		sites = append(sites, models.SiteConfig{Name: fmt.Sprintf("StatusFound%02d", i), URL: server.URL + fmt.Sprintf("/status/found/%02d/{username}", i), CheckType: "status_code", ErrorCode: 404, Weight: 10})
		sites = append(sites, models.SiteConfig{Name: fmt.Sprintf("StatusAbsent%02d", i), URL: server.URL + fmt.Sprintf("/status/absent/%02d/{username}", i), CheckType: "status_code", ErrorCode: 404, Weight: 10})
	}
	for i := 0; i < 12; i++ {
		sites = append(sites, models.SiteConfig{Name: fmt.Sprintf("MsgFound%02d", i), URL: server.URL + fmt.Sprintf("/msg/found/%02d/{username}", i), CheckType: "message", AbsenceStrs: []string{"profile does not exist"}, PresenceStrs: []string{"profile-marker"}, Weight: 10})
		sites = append(sites, models.SiteConfig{Name: fmt.Sprintf("MsgAbsent%02d", i), URL: server.URL + fmt.Sprintf("/msg/absent/%02d/{username}", i), CheckType: "message", AbsenceStrs: []string{"profile does not exist"}, PresenceStrs: []string{"profile-marker"}, Weight: 10})
	}
	// Six providers sharing one identical request (deduplication candidates).
	for i := 0; i < 6; i++ {
		sites = append(sites, models.SiteConfig{Name: fmt.Sprintf("Shared%02d", i), URL: server.URL + "/shared/{username}", CheckType: "status_code", ErrorCode: 404, Weight: 10})
	}
	return sites, server, requests
}

// TestOfflinePerformanceFixture is the rerunnable offline measurement
// required for username-search performance work. It asserts functional
// correctness and prints the measured metrics; it makes no timing asserts.
func TestOfflinePerformanceFixture(t *testing.T) {
	sites, server, requests := perfFixture(t)
	defer server.Close()
	bytesRead := &atomic.Int64{}
	base := &http.Client{Timeout: 30 * time.Second, Transport: &countingTransport{inner: http.DefaultTransport, bytes: bytesRead}}
	source := newTestSource(t, sites, network.NewRetryableClient(base, 0))

	start := time.Now()
	var order []string
	statuses := map[models.ResultStatus]int{}
	if err := source.SearchUsername(context.Background(), "perf_user", func(r models.Result) error {
		order = append(order, r.SiteName)
		statuses[r.Status]++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)

	if len(order) != len(sites) {
		t.Fatalf("expected %d results, got %d", len(sites), len(order))
	}
	if statuses[models.StatusFound] == 0 || statuses[models.StatusNotFound] == 0 {
		t.Fatalf("fixture must produce found and not_found results: %v", statuses)
	}
	t.Logf("PERF|sites=%d|results=%d|http_requests=%d|body_bytes_read=%d|duration=%s|statuses=%v",
		len(sites), len(order), requests.Load(), bytesRead.Load(), elapsed.Round(time.Millisecond), statuses)
}
