package evidence

import (
	"context"
	"time"
)

const SemanticVersion = "evidence-semantics-0.2"

type SemanticInputMode string

const (
	SemanticRedacted SemanticInputMode = "redacted"
	SemanticRaw      SemanticInputMode = "raw"
)

func semanticMode(mode SemanticInputMode) SemanticInputMode {
	if mode == "" {
		return SemanticRedacted
	}
	return mode
}

// SlotKey is a composite key: S12 and S13 each have two distinct slots.
type SlotKey struct {
	ID      string `json:"id"`
	Target  string `json:"target"`
	Subtype string `json:"subtype,omitempty"`
}

func (k SlotKey) String() string { return k.ID + "/" + k.Target + "/" + k.Subtype }

type SemanticDefinition struct {
	Key             SlotKey `json:"key"`
	Prerequisite    string  `json:"prerequisite"`
	ExplanationOnly bool    `json:"explanation_only"`
	Deduplication   string  `json:"deduplication"`
}

// SemanticMaterial is constructed by a trusted snapshot adapter, never from model
// claims. Redacted mode requires field-wise redaction; explicit raw mode retains
// actual text and leaves Redacted=false. Input mode is never inferred by LLM.
// Kind describes a parsed field/context, rather than a malicious/benign verdict.
type SemanticMaterial struct {
	ID                 string         `json:"id"`
	Kind               string         `json:"kind"`
	Scope              Scope          `json:"scope"`
	SnapshotVersion    int64          `json:"snapshot_version"`
	Window             AnalysisWindow `json:"window"`
	Provenance         Provenance     `json:"provenance"`
	Text               string         `json:"text"`
	FieldPath          string         `json:"field_path"`
	Redacted           bool           `json:"redacted"`
	Truncated          bool           `json:"truncated"`
	TransactionID      string         `json:"transaction_id,omitempty"`
	Direction          string         `json:"direction,omitempty"` // outbound or inbound, resolved by adapter
	RelatedIDs         []string       `json:"related_ids,omitempty"`
	Method             string         `json:"method,omitempty"`
	Protocol           string         `json:"protocol,omitempty"`
	Destination        string         `json:"destination,omitempty"`
	FieldNames         []string       `json:"field_names,omitempty"`
	Bytes              *uint64        `json:"bytes,omitempty"`
	Sequence           *uint64        `json:"sequence,omitempty"`
	AssetID            string         `json:"asset_id,omitempty"`
	Role               string         `json:"role,omitempty"`
	EventID            string         `json:"event_id,omitempty"`
	AdjudicationID     string         `json:"adjudication_id,omitempty"`
	AdjudicationSource string         `json:"adjudication_source,omitempty"`
	FalsePositive      bool           `json:"false_positive,omitempty"`
	// DecodeSteps reference actual encoded/decoded materials, checked by code.
	DecodeSteps []SemanticDecodeStep `json:"decode_steps,omitempty"`
}

type SemanticDecodeStep struct {
	Encoding string `json:"encoding"` // base64, base64url, hex
	InputID  string `json:"input_id"`
	OutputID string `json:"output_id"`
}

// PropositionID is assigned by the adapter to one operation/transfer, not by the
// model. Distinct operations must use distinct IDs, even within the same scope.
type SemanticSubject struct {
	InputMode     SemanticInputMode  `json:"-"` // assigned from request by the engine
	ID            string             `json:"id"`
	PropositionID string             `json:"proposition_id"`
	Scope         Scope              `json:"scope"`
	Window        AnalysisWindow     `json:"window"`
	Facts         []Finding          `json:"facts"`
	Materials     []SemanticMaterial `json:"materials"`
}

type SemanticRequest struct {
	InputMode       SemanticInputMode `json:"input_mode,omitempty"`
	EventID         string            `json:"event_id"`
	SnapshotVersion int64             `json:"snapshot_version"`
	Subjects        []SemanticSubject `json:"subjects"`
	// nil selects applicable slots; an explicit empty slice runs none.
	Slots []SlotKey `json:"slots"`
}

type SemanticConfig struct {
	MaxTasks         int
	MaxInputBytes    int // includes system prompt; bytes are NOT tokenizer tokens
	MaxOutputBytes   int
	MaxMaterialBytes int
	MaxOutputTokens  int
	Timeout          time.Duration
	// Optional actual tokenizer. Required when MaxInputTokens is configured.
	CountTokens    func(system, user string) (int, error)
	MaxInputTokens int
}

func DefaultSemanticConfig() SemanticConfig {
	return SemanticConfig{MaxTasks: 8, MaxInputBytes: 12000, MaxOutputBytes: 16000,
		MaxMaterialBytes: 512, MaxOutputTokens: 2000, Timeout: 60 * time.Second}
}

type SemanticCall struct {
	System          string
	Prompt          string
	MaxOutputTokens int
}

// Complete must enforce MaxOutputTokens and return an error for transport/model
// truncation. A plain Chat interface cannot enforce this per-call token contract.
type SemanticModel interface {
	Complete(context.Context, SemanticCall) (string, error)
}

type DeliveredMaterial struct {
	Redacted       bool     `json:"redacted"`
	ID             string   `json:"id"`
	Kind           string   `json:"kind"`
	Text           string   `json:"text"`
	FieldPath      string   `json:"field_path"`
	SourceIDs      []string `json:"source_ids"`
	SourceVersion  string   `json:"source_version"`
	SHA256         string   `json:"sha256"` // hash of actual pre-clipping text in this mode
	Truncated      bool     `json:"truncated"`
	AdjudicationID string   `json:"adjudication_id,omitempty"`
	TransactionID  string   `json:"transaction_id,omitempty"`
	Direction      string   `json:"direction,omitempty"`
	RelatedIDs     []string `json:"related_ids,omitempty"`
	Method         string   `json:"method,omitempty"`
	Protocol       string   `json:"protocol,omitempty"`
	Destination    string   `json:"destination,omitempty"`
	FieldNames     []string `json:"field_names,omitempty"`
	Bytes          *uint64  `json:"bytes,omitempty"`
	Sequence       *uint64  `json:"sequence,omitempty"`
	AssetID        string   `json:"asset_id,omitempty"`
	Role           string   `json:"role,omitempty"`
}

type SemanticFactRef struct {
	ID        string   `json:"id"`
	Status    Status   `json:"status"`
	SourceIDs []string `json:"source_ids"`
}

type SemanticTask struct {
	InputMode       SemanticInputMode   `json:"input_mode"`
	ID              string              `json:"task_id"`
	Slot            SemanticDefinition  `json:"slot"`
	SubjectID       string              `json:"subject_id"`
	PropositionID   string              `json:"proposition_id"`
	Scope           Scope               `json:"scope"`
	Window          AnalysisWindow      `json:"window"`
	MaxStrength     string              `json:"max_strength"`
	Materials       []DeliveredMaterial `json:"materials"`
	Facts           []SemanticFactRef   `json:"facts"`
	NonAdditiveWith []string            `json:"non_additive_with,omitempty"`
}

type SemanticExecution struct {
	Slot      SlotKey `json:"slot"`
	SubjectID string  `json:"subject_id"`
	TaskID    string  `json:"task_id,omitempty"`
	Status    string  `json:"status"`
	Reason    string  `json:"reason"`
}

type SemanticPlan struct {
	InputMode       SemanticInputMode   `json:"input_mode"`
	EventID         string              `json:"event_id"`
	SnapshotVersion int64               `json:"snapshot_version"`
	RuleVersion     string              `json:"rule_version"`
	Tasks           []SemanticTask      `json:"tasks"`
	Executions      []SemanticExecution `json:"executions"`
	Prompt          string              `json:"-"`
	ContextSHA256   string              `json:"context_sha256"`
	InputBytes      int                 `json:"input_bytes"`
	InputTokens     int                 `json:"input_tokens,omitempty"`
	Budget          SemanticBudget      `json:"budget"`
}

type SemanticBudget struct {
	MaxTasks         int   `json:"max_tasks"`
	MaxInputBytes    int   `json:"max_input_bytes"`
	MaxInputTokens   int   `json:"max_input_tokens,omitempty"`
	MaxMaterialBytes int   `json:"max_material_bytes"`
	MaxOutputBytes   int   `json:"max_output_bytes"`
	MaxOutputTokens  int   `json:"max_output_tokens"`
	TimeoutMillis    int64 `json:"timeout_ms"`
}

type SemanticQuote struct {
	MaterialID string `json:"material_id"`
	Excerpt    string `json:"excerpt"`
}

// The model may supply interpretation only; scope, slot, sources, versions,
// statistical values and scores are assigned/retained by code.
type SemanticItem struct {
	TaskID           string          `json:"task_id"`
	Judgement        string          `json:"judgement"` // support / contradict / neutral
	Strength         string          `json:"strength"`  // none / weak / medium / strong
	MaterialRefs     []string        `json:"material_refs"`
	FactRefs         []string        `json:"fact_refs"`
	AdjudicationRefs []string        `json:"adjudication_refs"`
	Quotes           []SemanticQuote `json:"quotes"`
	Explanation      string          `json:"explanation"`
	Alternatives     []string        `json:"alternatives"`
	Gaps             []string        `json:"gaps"`
}

type SemanticFinding struct {
	SemanticItem
	Slot            SlotKey        `json:"slot"`
	SubjectID       string         `json:"subject_id"`
	PropositionID   string         `json:"proposition_id"`
	Scope           Scope          `json:"scope"`
	Window          AnalysisWindow `json:"window"`
	SnapshotVersion int64          `json:"snapshot_version"`
	RuleVersion     string         `json:"rule_version"`
	ExplanationOnly bool           `json:"explanation_only"`
	NonAdditiveWith []string       `json:"non_additive_with,omitempty"`
	DuplicateOf     string         `json:"duplicate_of,omitempty"`
	Limitations     []string       `json:"limitations"`
}

type SemanticResult struct {
	Plan           SemanticPlan      `json:"plan"`
	Findings       []SemanticFinding `json:"semantic_findings"`
	Calls          int               `json:"calls"`
	ResponseSHA256 string            `json:"response_sha256,omitempty"`
}
