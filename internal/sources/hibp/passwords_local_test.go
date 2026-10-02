package hibp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/security"
)

func TestLocalPasswordLifecycleAndResults(t *testing.T) {
	const input = "correct horse battery staple"
	const full = "ABF7AAD6438836DBE526AA231ABDE2D0EEF74D42"
	for _, tc := range []string{"found", "absent", "lookup-error", "cancelled", "consumer-error"} {
		t.Run(tc, func(t *testing.T) {
			secret := security.NewSecret(input)
			shared := secret
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc == "cancelled" {
				cancel()
			}
			source := &LocalPasswordSource{lookup: func(ctx context.Context, key [20]byte) (uint64, error) {
				if !shared.Empty() {
					t.Error("plaintext retained during database lookup")
				}
				if strings.ToUpper(hex.EncodeToString(key[:])) != full {
					t.Error("incorrect local digest")
				}
				if tc == "lookup-error" {
					return 0, errors.New(input + full)
				}
				if tc == "absent" {
					return 0, nil
				}
				return 42, nil
			}}
			var result models.Result
			err := source.SearchPassword(ctx, secret, func(r models.Result) error {
				result = r
				if tc == "consumer-error" {
					return errors.New(input + full)
				}
				return nil
			})
			meaning := models.MeaningObservation
			if result.Status == models.StatusNotFound {
				meaning = models.MeaningAbsence
			}
			if result.Status == models.StatusError {
				meaning = models.MeaningError
			}
			if result.EvidenceSemantics() != (models.EvidenceSemantics{Kind: models.ObservationPassword, Meaning: meaning}) {
				t.Fatal("password corpus semantics changed")
			}
			if !shared.Empty() {
				t.Fatal("shared secret retained")
			}
			raw, _ := json.Marshal(result)
			text := string(raw) + fmt.Sprint(err)
			for _, s := range []string{input, full, strings.ToLower(full), full[:5], full[5:]} {
				if strings.Contains(text, s) {
					t.Fatal("local source leaked input or lookup material")
				}
			}
			if tc == "found" || tc == "absent" {
				if err != nil || result.Confidence != 100 {
					t.Fatal("incorrect successful result")
				}
				if (result.Status == models.StatusFound) != (tc == "found") {
					t.Fatal("incorrect membership")
				}
			} else if err == nil {
				t.Fatal("failure was not returned")
			}
			if tc == "lookup-error" || tc == "cancelled" {
				if result.Status != models.StatusError || result.Metadata["pwned"] != "" {
					t.Fatal("error represented as absence")
				}
			}
		})
	}
}
