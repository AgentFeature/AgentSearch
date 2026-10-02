package models

// ObservationKind names the scope of a lookup, not a verdict about its target.
// Unknown integrations do not inherit a known provider's evidence contract.
type ObservationKind string

const (
	ObservationUnknown            ObservationKind = "unknown"
	ObservationWebsite            ObservationKind = "website_detection"
	ObservationBreach             ObservationKind = "breach_association"
	ObservationBitcoinLabels      ObservationKind = "bitcoin_label_association"
	ObservationBitcoinTransaction ObservationKind = "bitcoin_transaction"
	ObservationBitcoin            ObservationKind = "bitcoin_address"
	ObservationIP                 ObservationKind = "ip_profile"
	ObservationDomain             ObservationKind = "domain_profile"
	ObservationPassword           ObservationKind = "password_corpus"
)

// EvidenceMeaning interprets a source result within its lookup scope. Absence
// is limited to a supported corpus lookup, never a universal negative or safety
// assertion. An observation can be a detector inference, not a directly proven fact.
type EvidenceMeaning string

const (
	MeaningObservation EvidenceMeaning = "observation"
	MeaningAbsence     EvidenceMeaning = "absence"
	MeaningError       EvidenceMeaning = "error"
	MeaningUnknown     EvidenceMeaning = "unknown"
)

// EvidenceSemantics is an on-demand internal interpretation, not stored in Result
// or added to its JSON/CSV/report schemas. Existing source/status/evidence fields
// remain the provenance record. This view copies no target, evidence value, URL,
// arbitrary source text, score or password material; it is not origin attestation.
type EvidenceSemantics struct {
	Kind    ObservationKind
	Meaning EvidenceMeaning
}

// EvidenceSemantics interprets declared provenance, without changing the result
// or inspecting free-form metadata/error text. Use explicit provider statuses:
// an unspecified status does not establish absence. Normalized's legacy default
// inference remains unchanged for compatibility, not a new evidence guarantee.
func (r Result) EvidenceSemantics() EvidenceSemantics {
	view := EvidenceSemantics{Kind: ObservationUnknown, Meaning: MeaningUnknown}
	switch {
	case r.Source == "bitcoin-tx" && r.SourceType == SourceAPI && r.TargetType == TargetBitcoinTransaction:
		view.Kind = ObservationBitcoinTransaction
	case r.ProviderLabelObservation():
		view.Kind = ObservationBitcoinLabels
	case r.Source == "bitcoin" && r.SourceType == SourceAPI && r.TargetType == TargetBitcoin:
		view.Kind = ObservationBitcoin
	case r.Source == "ipinfo" && r.SourceType == SourceAPI && r.TargetType == TargetIP:
		view.Kind = ObservationIP
	case r.SourceType == SourceWebsite && (r.TargetType == TargetUsername || r.TargetType == TargetEmail):
		view.Kind = ObservationWebsite
	case r.Source == "hibp" && r.SourceType == SourceAPI && r.TargetType == TargetEmail:
		view.Kind = ObservationBreach
	case r.Source == "securitytrails" && r.SourceType == SourceAPI && r.TargetType == TargetDomain:
		view.Kind = ObservationDomain
	case r.TargetType == TargetPassword && ((r.Source == "pwned-passwords" && r.SourceType == SourceAPI) || (r.Source == "pwned-passwords-local" && r.SourceType == SourceLocal)):
		view.Kind = ObservationPassword
	}
	switch r.Status {
	case StatusError:
		view.Meaning = MeaningError
	case StatusFound:
		view.Meaning = MeaningObservation
	case StatusNotFound:
		switch view.Kind {
		case ObservationBreach, ObservationPassword, ObservationBitcoinTransaction:
			view.Meaning = MeaningAbsence
		case ObservationBitcoinLabels:
			// Provider-scoped no-label is still an observation, not identity absence.
			view.Meaning = MeaningObservation
		case ObservationWebsite:
			// A rule-generated negative, including fallback HTTP-status heuristics,
			// is an observation of detector output, not verified profile absence.
			view.Meaning = MeaningObservation
		}
	case "":
		// Preserve only positive/error legacy signals, never infer negative evidence
		// from an empty record. Do not inspect Target to guess a sensitive type.
		if r.Error != "" {
			view.Meaning = MeaningError
		} else if r.Found {
			view.Meaning = MeaningObservation
		}
	}
	return view
}
