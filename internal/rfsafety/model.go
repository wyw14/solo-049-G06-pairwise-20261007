// Package rfsafety orchestrates transmit-enable command tickets. A ticket
// combines the frequency plan, the transmit inhibit evidence, the antenna
// state and the current pass phase, and must survive request, review and
// execution gates before a chain may radiate. Transmit is never enabled
// without a matching pass, a matching decoder epoch and accounted
// suppression evidence.
package rfsafety

import (
	"fmt"
	"strings"
	"time"

	"orbitlink/internal/antenna"
	passsvc "orbitlink/internal/pass"
	"orbitlink/internal/rf"
)

type TicketStage string

const (
	StageRequested TicketStage = "requested"
	StageReviewed  TicketStage = "reviewed"
	StageExecuted  TicketStage = "executed"
	StageRevoked   TicketStage = "revoked"
)

// Evidence is a point-in-time snapshot of every safety input a ticket
// depends on. Execution compares the reviewed snapshot against a fresh one
// and refuses to radiate when anything drifted.
type Evidence struct {
	PassPhase         passsvc.Phase `json:"pass_phase"`
	WindowRevision    int64         `json:"window_revision"`
	DecoderEpoch      int64         `json:"decoder_epoch"`
	ChainAssigned     bool          `json:"chain_assigned"`
	AntennaID         string        `json:"antenna_id"`
	AntennaMode       antenna.Mode  `json:"antenna_mode"`
	AntennaOwnerPass  string        `json:"antenna_owner_pass,omitempty"`
	AntennaGeneration int64         `json:"antenna_owner_generation,omitempty"`
	TransmitEnabled   bool          `json:"transmit_enabled"`
	InhibitOperation  string        `json:"inhibit_operation,omitempty"`
	CapturedAt        time.Time     `json:"captured_at"`
}

func (e Evidence) matches(other Evidence) bool {
	e.CapturedAt = time.Time{}
	other.CapturedAt = time.Time{}
	return e == other
}

type Ticket struct {
	ID                     string      `json:"id"`
	PassID                 string      `json:"pass_id"`
	ChainID                string      `json:"chain_id"`
	Plan                   rf.Plan     `json:"plan"`
	Epoch                  int64       `json:"epoch"`
	ClearInhibitOperation  string      `json:"clear_inhibit_operation,omitempty"`
	Stage                  TicketStage `json:"stage"`
	RequestedBy            string      `json:"requested_by"`
	ReviewedBy             string      `json:"reviewed_by,omitempty"`
	RequestEvidence        Evidence    `json:"request_evidence"`
	ReviewEvidence         *Evidence   `json:"review_evidence,omitempty"`
	RevokeReason           string      `json:"revoke_reason,omitempty"`
	RevokeInhibitOperation string      `json:"revoke_inhibit_operation,omitempty"`
	CreatedAt              time.Time   `json:"created_at"`
	UpdatedAt              time.Time   `json:"updated_at"`
}

func (t Ticket) open() bool {
	return t.Stage == StageRequested || t.Stage == StageReviewed || t.Stage == StageExecuted
}

type Request struct {
	PassID                string
	ChainID               string
	CenterHz              int64
	DopplerHz             int64
	Polarization          rf.Polarization
	Epoch                 int64
	ClearInhibitOperation string
	RequestedBy           string
}

// GateError reports every safety gate violation that blocked a transition.
type GateError struct {
	TicketID   string
	Violations []string
}

func (e *GateError) Error() string {
	return fmt.Sprintf("rf safety gates rejected ticket %s: %s", e.TicketID, strings.Join(e.Violations, "; "))
}
