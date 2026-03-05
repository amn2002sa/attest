package intent

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

// IntentStatus represents the status of an intent
type IntentStatus string

const (
	IntentStatusOpen     IntentStatus = "open"
	IntentStatusProgress IntentStatus = "in_progress"
	IntentStatusComplete IntentStatus = "completed"
	IntentStatusFailed   IntentStatus = "failed"
	IntentStatusCanceled IntentStatus = "canceled"
)

// Intent represents an agent intent/goal
type Intent struct {
	ID                 string       `json:"id"`
	Goal               string       `json:"goal"`
	Description        string       `json:"description,omitempty"`
	TicketID           string       `json:"ticketId,omitempty"`
	Constraints        []string     `json:"constraints,omitempty"`
	AcceptanceCriteria []string     `json:"acceptanceCriteria,omitempty"`
	Status             IntentStatus `json:"status"`
	CreatedAt          time.Time    `json:"createdAt"`
	ClosedAt           *time.Time   `json:"closedAt,omitempty"`
	Metadata           IntentMeta   `json:"metadata,omitempty"`
}

// IntentMeta contains additional metadata about an intent
type IntentMeta struct {
	Priority   string            `json:"priority,omitempty"`
	Assignee   string            `json:"assignee,omitempty"`
	Epic       string            `json:"epic,omitempty"`
	Labels     []string          `json:"labels,omitempty"`
	CustomData map[string]string `json:"customData,omitempty"`
}

// CreateIntent creates a new intent
func CreateIntent(goal string, description, ticketID string, constraints, criteria []string) *Intent {
	id := generateIntentID(goal)

	return &Intent{
		ID:                 id,
		Goal:               goal,
		Description:        description,
		TicketID:           ticketID,
		Constraints:        constraints,
		AcceptanceCriteria: criteria,
		Status:             IntentStatusOpen,
		CreatedAt:          time.Now().UTC(),
	}
}

// Close marks an intent as completed
func (i *Intent) Close(success bool) {
	now := time.Now().UTC()
	i.ClosedAt = &now
	if success {
		i.Status = IntentStatusComplete
	} else {
		i.Status = IntentStatusFailed
	}
}

// Progress marks intent as in progress
func (i *Intent) Progress() {
	i.Status = IntentStatusProgress
}

// Cancel cancels the intent
func (i *Intent) Cancel() {
	now := time.Now().UTC()
	i.ClosedAt = &now
	i.Status = IntentStatusCanceled
}

// ToJSON returns the intent as JSON
func (i *Intent) ToJSON() ([]byte, error) {
	return json.MarshalIndent(i, "", "  ")
}

// FromJSON parses an intent from JSON
func FromJSON(data []byte) (*Intent, error) {
	var intent Intent
	if err := json.Unmarshal(data, &intent); err != nil {
		return nil, fmt.Errorf("failed to parse intent: %w", err)
	}
	return &intent, nil
}

// generateIntentID generates a unique ID for an intent
func generateIntentID(goal string) string {
	data := fmt.Sprintf("intent:%s:%s", goal, time.Now().UTC().Format(time.RFC3339))
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("int:%x", hash[:8])
}

// IntentStore provides storage for intents
type IntentStore struct {
	// Database operations will be implemented here
}

// NewIntentStore creates a new intent store
func NewIntentStore() *IntentStore {
	return &IntentStore{}
}

// Save stores an intent
func (s *IntentStore) Save(intent *Intent) error {
	// TODO: Implement database save
	return nil
}

// Get retrieves an intent by ID
func (s *IntentStore) Get(id string) (*Intent, error) {
	// TODO: Implement database get
	return nil, nil
}

// List returns intents with optional filtering
func (s *IntentStore) List(status IntentStatus, limit int) ([]*Intent, error) {
	// TODO: Implement database list
	return nil, nil
}

// FindByTicket finds an intent by ticket ID
func (s *IntentStore) FindByTicket(ticketID string) (*Intent, error) {
	// TODO: Implement database search
	return nil, nil
}

// FindByGoal searches intents by goal text
func (s *IntentStore) FindByGoal(search string, limit int) ([]*Intent, error) {
	// TODO: Implement database search
	return nil, nil
}

// LinkAttestation links an attestation to an intent
func (s *IntentStore) LinkAttestation(intentID, attestationID string) error {
	// TODO: Implement database link
	return nil
}

// GetAttestations returns all attestations linked to an intent
func (s *IntentStore) GetAttestations(intentID string) ([]string, error) {
	// TODO: Implement database query
	return nil, nil
}

// IntentInfo represents intent data for display
type IntentInfo struct {
	ID       string       `json:"id"`
	Goal     string       `json:"goal"`
	TicketID string       `json:"ticketId,omitempty"`
	Status   IntentStatus `json:"status"`
	Actions  int          `json:"actionCount"`
	Created  time.Time    `json:"createdAt"`
}

// ToDisplayInfo converts an Intent to IntentInfo for display
func (i *Intent) ToDisplayInfo(actionCount int) *IntentInfo {
	return &IntentInfo{
		ID:       i.ID,
		Goal:     i.Goal,
		TicketID: i.TicketID,
		Status:   i.Status,
		Actions:  actionCount,
		Created:  i.CreatedAt,
	}
}

// PrettyPrint prints an intent in a human-readable format
func (i *Intent) PrettyPrint() string {
	return fmt.Sprintf(`Intent ID:      %s
Goal:           %s
Description:    %s
Ticket:         %s
Status:         %s
Created:        %s
Constraints:    %v
Criteria:       %v
`,
		i.ID,
		i.Goal,
		i.Description,
		i.TicketID,
		i.Status,
		i.CreatedAt.Format(time.RFC3339),
		i.Constraints,
		i.AcceptanceCriteria,
	)
}

// IntentGraph represents a graph of intents and their actions
type IntentGraph struct {
	Root  *Intent      `json:"root"`
	Links []IntentLink `json:"links"`
}

// IntentLink represents a link between intent and attestation
type IntentLink struct {
	IntentID      string `json:"intentId"`
	AttestationID string `json:"attestationId"`
	ActionType    string `json:"actionType"`
	Timestamp     string `json:"timestamp"`
}
