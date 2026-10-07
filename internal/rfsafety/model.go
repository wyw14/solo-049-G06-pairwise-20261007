// Package rfsafety orchestrates transmit command tickets. A ticket combines
// the frequency plan, the transmit inhibit proof, the antenna state and the
// current pass phase into one auditable request/review/execute/revoke flow.
// Transmit is never enabled without a matching pass, decoder epoch and
// confirmed inhibit evidence.
package rfsafety

import (
	"fmt"
	"time"

	"orbitlink/internal/antenna"
	passsvc "orbitlink/internal/pass"
	"orbitlink/internal/rf"
)

// Status is the lifecycle state of a transmit command ticket.
type Status string

const (
	Requested Status = "requested"
	Reviewed  Status = "reviewed"
	Executed  Status = "executed"
	Revoked   Status = "revoked"
)

// Evidence binds a ticket to the live station state that authorizes transmit.
type Evidence struct {
	Plan           rf.Plan         `json:"plan"`
	Inhibit        rf.InhibitProof `json:"inhibit"`
	AntennaMode    antenna.Mode    `json:"antenna_mode"`
	PassPhase      passsvc.Phase   `json:"pass_phase"`
	Epoch          int64           `json:"epoch"`
	WindowRevision int64           `json:"window_revision"`
}

// Ticket is one command ticket authorizing transmit on one RF chain.
type Ticket struct {
	ID           string    `json:"id"`
	PassID       string    `json:"pass_id"`
	ChainID      string    `json:"chain_id"`
	AntennaID    string    `json:"antenna_id"`
	Status       Status    `json:"status"`
	Evidence     Evidence  `json:"evidence"`
	RequestedBy  string    `json:"requested_by"`
	ReviewedBy   string    `json:"reviewed_by,omitempty"`
	RequestedAt  time.Time `json:"requested_at"`
	ReviewedAt   time.Time `json:"reviewed_at,omitempty"`
	ExecutedAt   time.Time `json:"executed_at,omitempty"`
	RevokedAt    time.Time `json:"revoked_at,omitempty"`
	RevokeReason string    `json:"revoke_reason,omitempty"`
}

func (t Ticket) Validate() error {
	if t.ID == "" || t.PassID == "" || t.ChainID == "" || t.AntennaID == "" {
		return fmt.Errorf("ticket, pass, RF chain and antenna identity are required")
	}
	if t.RequestedBy == "" {
		return fmt.Errorf("ticket requester is required")
	}
	if t.Evidence.Inhibit.Operation == "" || !t.Evidence.Inhibit.Confirmed {
		return fmt.Errorf("ticket requires confirmed transmit inhibit evidence")
	}
	if t.Evidence.Epoch < 1 {
		return fmt.Errorf("ticket requires a decoder epoch")
	}
	if t.Evidence.WindowRevision < 1 {
		return fmt.Errorf("ticket requires a pass window revision")
	}
	if t.Evidence.Plan.CenterHz <= 0 {
		return fmt.Errorf("ticket requires a frequency plan")
	}
	switch t.Status {
	case Requested, Reviewed, Executed, Revoked:
		return nil
	default:
		return fmt.Errorf("unknown ticket status %q", t.Status)
	}
}
