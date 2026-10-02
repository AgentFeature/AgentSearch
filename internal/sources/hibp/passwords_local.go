package hibp

import (
	"context"
	"crypto/sha1" // HIBP interoperability, not password storage.
	"fmt"
	"strconv"
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/passworddb"
	"github.com/AgentFeature/agentsearch/internal/security"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

// LocalPasswordSource consumes one secret and uses an app-owned immutable snapshot.
// It has no HTTP client, credential access, fallback, or snapshot-refresh policy.
type LocalPasswordSource struct {
	lookup func(context.Context, [20]byte) (uint64, error)
	info   passworddb.Info
}

func NewLocalPasswordSource(db *passworddb.Snapshot) (*LocalPasswordSource, error) {
	if db == nil {
		return nil, fmt.Errorf("local password source requires a snapshot")
	}
	return &LocalPasswordSource{lookup: db.Lookup, info: db.Info()}, nil
}
func (*LocalPasswordSource) Name() string            { return "pwned-passwords-local" }
func (*LocalPasswordSource) Type() models.SourceType { return models.SourceLocal }
func (s *LocalPasswordSource) SearchPassword(ctx context.Context, password security.Secret, emit sources.Emit) error {
	defer password.Destroy()
	if emit == nil {
		return fmt.Errorf("local password source requires a result consumer")
	}
	start := time.Now()
	var key [20]byte
	defer clear(key[:])
	err := password.Consume(func(value []byte) error { key = sha1.Sum(value); return nil })
	var count uint64
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		count, err = s.lookup(ctx, key)
	}
	clear(key[:])
	if err == nil {
		err = ctx.Err()
	}
	err = passworddb.SafeError(err)
	r := models.Result{Source: s.Name(), SourceType: s.Type(), TargetType: models.TargetPassword, Target: security.Redacted, SiteName: "Have I Been Pwned / Pwned Passwords (local)", URL: "https://haveibeenpwned.com/Passwords", Duration: time.Since(start), Metadata: map[string]string{"method": "sha1-offline", "dataset_id": s.info.DatasetID, "acquired_at": s.info.AcquiredAt}}
	if s.info.Recovered {
		r.Metadata["activation_recovered"] = "true"
	}
	if err != nil {
		r.Status = models.StatusError
		r.Error = err.Error()
		r.Metadata["error_kind"] = passworddb.ErrorKind(err)
	} else {
		r.Status = models.StatusNotFound
		r.Confidence = 100
		if count > 0 {
			r.Status = models.StatusFound
		}
		r.Metadata["pwned"] = strconv.FormatBool(count > 0)
		r.Metadata["occurrences"] = strconv.FormatUint(count, 10)
	}
	if emit(r.Normalized()) != nil {
		return fmt.Errorf("local password result consumer failed")
	}
	return err
}

var _ sources.PasswordSearcher = (*LocalPasswordSource)(nil)
var _ sources.Source = (*LocalPasswordSource)(nil)
