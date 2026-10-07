package rfsafety

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"orbitlink/internal/antenna"
	"orbitlink/internal/audit"
	passsvc "orbitlink/internal/pass"
	"orbitlink/internal/rf"
	"orbitlink/internal/store"
)

type PassSource interface {
	Get(id string) (passsvc.Pass, bool)
}

type AntennaSource interface {
	State(id string) (antenna.State, bool)
}

type TransmitControl interface {
	Apply(plan rf.Plan) (rf.State, error)
	EnableTransmit(chainID string) error
	Inhibit(ctx context.Context, chainID, operationID string) (rf.InhibitProof, error)
	VerifyInhibit(chainID, operationID string) bool
	State(chainID string) (rf.State, bool)
}

// Orchestrator issues and supervises transmit-enable command tickets. The
// orchestrator lock is held across RF controller calls so a gate decision
// and its actuation stay atomic; the RF controller never calls back, so the
// lock ordering is one-directional.
type Orchestrator struct {
	mu       sync.RWMutex
	path     string
	tickets  map[string]Ticket
	passes   PassSource
	antennas AntennaSource
	radio    TransmitControl
	now      func() time.Time
	audit    *audit.Trail
}

func NewOrchestrator(paths store.Paths, trail *audit.Trail, passes PassSource, antennas AntennaSource, radio TransmitControl, now func() time.Time) (*Orchestrator, error) {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	orchestrator := &Orchestrator{
		path: paths.Snapshot("rf-tickets"), tickets: make(map[string]Ticket),
		passes: passes, antennas: antennas, radio: radio, now: now, audit: trail,
	}
	var tickets []Ticket
	found, err := store.ReadJSON(orchestrator.path, &tickets)
	if err != nil {
		return nil, err
	}
	if found {
		for _, ticket := range tickets {
			orchestrator.tickets[ticket.ID] = ticket
		}
	}
	return orchestrator, nil
}

// Request files a new transmit-enable ticket. Static facts are validated
// here; the live safety gates run at review and again at execution.
func (o *Orchestrator) Request(request Request) (Ticket, error) {
	if request.PassID == "" || request.ChainID == "" || request.RequestedBy == "" {
		return Ticket{}, fmt.Errorf("pass, RF chain and requesting operator are required")
	}
	if request.CenterHz <= 0 {
		return Ticket{}, fmt.Errorf("frequency plan requires a positive center frequency")
	}
	if request.Epoch < 1 {
		return Ticket{}, fmt.Errorf("ticket epoch must reference a decoder epoch")
	}
	value, found := o.passes.Get(request.PassID)
	if !found {
		return Ticket{}, fmt.Errorf("pass %s not found", request.PassID)
	}
	if !chainAssigned(value, request.ChainID) {
		return Ticket{}, fmt.Errorf("RF chain %s is not assigned to pass %s", request.ChainID, request.PassID)
	}
	if _, found := o.radio.State(request.ChainID); !found {
		return Ticket{}, fmt.Errorf("RF chain %s not found", request.ChainID)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, ticket := range o.tickets {
		if ticket.ChainID == request.ChainID && ticket.open() {
			return Ticket{}, fmt.Errorf("RF chain %s already has an open ticket %s", request.ChainID, ticket.ID)
		}
	}
	evidence, err := o.snapshotLocked(request.PassID, request.ChainID)
	if err != nil {
		return Ticket{}, err
	}
	now := o.now().UTC()
	ticket := Ticket{
		ID: uuid.NewString(), PassID: request.PassID, ChainID: request.ChainID,
		Plan: rf.Plan{
			PassID: request.PassID, ChainID: request.ChainID, CenterHz: request.CenterHz,
			DopplerHz: request.DopplerHz, Polarization: request.Polarization,
		},
		Epoch: request.Epoch, ClearInhibitOperation: request.ClearInhibitOperation,
		Stage: StageRequested, RequestedBy: request.RequestedBy,
		RequestEvidence: evidence, CreatedAt: now, UpdatedAt: now,
	}
	o.tickets[ticket.ID] = ticket
	if err := o.flushLocked(); err != nil {
		delete(o.tickets, ticket.ID)
		return Ticket{}, err
	}
	_, _ = o.audit.Record(audit.Event{Component: "rfsafety", Action: "ticket.requested", Subject: ticket.ID, Fields: map[string]any{"pass_id": ticket.PassID, "chain_id": ticket.ChainID, "epoch": ticket.Epoch, "requested_by": ticket.RequestedBy}})
	return ticket, nil
}

// Review certifies that every safety gate currently holds. A second operator
// must perform the review.
func (o *Orchestrator) Review(ticketID, reviewer string) (Ticket, error) {
	if reviewer == "" {
		return Ticket{}, fmt.Errorf("reviewing operator is required")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	ticket, found := o.tickets[ticketID]
	if !found {
		return Ticket{}, fmt.Errorf("ticket %s not found", ticketID)
	}
	if ticket.Stage != StageRequested {
		return Ticket{}, fmt.Errorf("ticket %s cannot be reviewed from stage %s", ticketID, ticket.Stage)
	}
	if reviewer == ticket.RequestedBy {
		return Ticket{}, fmt.Errorf("review requires a second operator")
	}
	evidence, err := o.snapshotLocked(ticket.PassID, ticket.ChainID)
	if err != nil {
		return Ticket{}, err
	}
	if violations := o.gates(ticket, evidence); len(violations) > 0 {
		o.denyLocked(ticket, "ticket.review-denied", violations)
		return Ticket{}, &GateError{TicketID: ticketID, Violations: violations}
	}
	ticket.Stage = StageReviewed
	ticket.ReviewedBy = reviewer
	ticket.ReviewEvidence = &evidence
	ticket.UpdatedAt = o.now().UTC()
	o.tickets[ticket.ID] = ticket
	if err := o.flushLocked(); err != nil {
		return Ticket{}, err
	}
	_, _ = o.audit.Record(audit.Event{Component: "rfsafety", Action: "ticket.reviewed", Subject: ticket.ID, Fields: map[string]any{"reviewed_by": reviewer, "epoch": evidence.DecoderEpoch, "pass_phase": string(evidence.PassPhase)}})
	return ticket, nil
}

// Execute applies the ticket frequency plan and enables transmit, but only
// when the reviewed evidence still matches the live snapshot exactly.
func (o *Orchestrator) Execute(ctx context.Context, ticketID string) (Ticket, error) {
	select {
	case <-ctx.Done():
		return Ticket{}, fmt.Errorf("ticket execution canceled: %w", ctx.Err())
	default:
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	ticket, found := o.tickets[ticketID]
	if !found {
		return Ticket{}, fmt.Errorf("ticket %s not found", ticketID)
	}
	if ticket.Stage != StageReviewed || ticket.ReviewEvidence == nil {
		return Ticket{}, fmt.Errorf("ticket %s cannot be executed from stage %s", ticketID, ticket.Stage)
	}
	evidence, err := o.snapshotLocked(ticket.PassID, ticket.ChainID)
	if err != nil {
		return Ticket{}, err
	}
	if violations := o.gates(ticket, evidence); len(violations) > 0 {
		o.denyLocked(ticket, "ticket.execute-denied", violations)
		return Ticket{}, &GateError{TicketID: ticketID, Violations: violations}
	}
	if !evidence.matches(*ticket.ReviewEvidence) {
		ticket.Stage = StageRequested
		ticket.ReviewedBy = ""
		ticket.ReviewEvidence = nil
		ticket.UpdatedAt = o.now().UTC()
		o.tickets[ticket.ID] = ticket
		if err := o.flushLocked(); err != nil {
			return Ticket{}, err
		}
		o.denyLocked(ticket, "ticket.review-staled", []string{"safety evidence changed since review; ticket returned to requested"})
		return Ticket{}, fmt.Errorf("ticket %s evidence changed since review; re-review required", ticketID)
	}
	if _, err := o.radio.Apply(ticket.Plan); err != nil {
		return Ticket{}, err
	}
	if err := o.radio.EnableTransmit(ticket.ChainID); err != nil {
		return Ticket{}, err
	}
	ticket.Stage = StageExecuted
	ticket.UpdatedAt = o.now().UTC()
	o.tickets[ticket.ID] = ticket
	if err := o.flushLocked(); err != nil {
		return Ticket{}, err
	}
	_, _ = o.audit.Record(audit.Event{Component: "rfsafety", Action: "ticket.executed", Subject: ticket.ID, Fields: map[string]any{"pass_id": ticket.PassID, "chain_id": ticket.ChainID, "center_hz": ticket.Plan.CenterHz, "doppler_hz": ticket.Plan.DopplerHz, "epoch": ticket.Epoch}})
	return ticket, nil
}

// Revoke withdraws a ticket at any stage. An executed ticket is only
// revoked after the chain is verifiably inhibited again.
func (o *Orchestrator) Revoke(ctx context.Context, ticketID, reason string) (Ticket, error) {
	if reason == "" {
		return Ticket{}, fmt.Errorf("revoke reason is required")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	ticket, found := o.tickets[ticketID]
	if !found {
		return Ticket{}, fmt.Errorf("ticket %s not found", ticketID)
	}
	if ticket.Stage == StageRevoked {
		return Ticket{}, fmt.Errorf("ticket %s is already revoked", ticketID)
	}
	operation := ""
	if ticket.Stage == StageExecuted {
		operation = "revoke:" + ticket.ID
		proof, err := o.radio.Inhibit(ctx, ticket.ChainID, operation)
		if err != nil || !proof.Confirmed || !o.radio.VerifyInhibit(ticket.ChainID, operation) {
			if err == nil {
				err = fmt.Errorf("inhibit proof for %s could not be verified", ticket.ChainID)
			}
			_, _ = o.audit.Record(audit.Event{Component: "rfsafety", Action: "ticket.revoke-inhibit-failed", Subject: ticket.ID, Severity: audit.Critical, Operation: operation, Fields: map[string]any{"error": err.Error()}})
			return Ticket{}, fmt.Errorf("cannot revoke ticket %s without confirmed inhibit: %w", ticketID, err)
		}
	}
	ticket.Stage = StageRevoked
	ticket.RevokeReason = reason
	ticket.RevokeInhibitOperation = operation
	ticket.UpdatedAt = o.now().UTC()
	o.tickets[ticket.ID] = ticket
	if err := o.flushLocked(); err != nil {
		return Ticket{}, err
	}
	_, _ = o.audit.Record(audit.Event{Component: "rfsafety", Action: "ticket.revoked", Subject: ticket.ID, Operation: operation, Fields: map[string]any{"reason": reason, "was_executed": operation != ""}})
	return ticket, nil
}

func (o *Orchestrator) Get(ticketID string) (Ticket, bool) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	ticket, found := o.tickets[ticketID]
	return ticket, found
}

func (o *Orchestrator) List() []Ticket {
	o.mu.RLock()
	defer o.mu.RUnlock()
	values := make([]Ticket, 0, len(o.tickets))
	for _, ticket := range o.tickets {
		values = append(values, ticket)
	}
	return values
}

// snapshotLocked reads the live pass, antenna and RF chain state. Callers
// hold the lock so a decision and its evidence stay consistent.
func (o *Orchestrator) snapshotLocked(passID, chainID string) (Evidence, error) {
	value, found := o.passes.Get(passID)
	if !found {
		return Evidence{}, fmt.Errorf("pass %s not found", passID)
	}
	antennaState, found := o.antennas.State(value.AntennaID)
	if !found {
		return Evidence{}, fmt.Errorf("antenna %s not found", value.AntennaID)
	}
	rfState, found := o.radio.State(chainID)
	if !found {
		return Evidence{}, fmt.Errorf("RF chain %s not found", chainID)
	}
	return Evidence{
		PassPhase: value.Phase, WindowRevision: value.Window.Revision, DecoderEpoch: value.DecoderEpoch,
		ChainAssigned: chainAssigned(value, chainID),
		AntennaID:     antennaState.ID, AntennaMode: antennaState.Mode,
		AntennaOwnerPass: antennaState.OwnerPassID, AntennaGeneration: antennaState.OwnerGeneration,
		TransmitEnabled: rfState.TransmitEnabled, InhibitOperation: rfState.InhibitOperation,
		CapturedAt: o.now().UTC(),
	}, nil
}

// gates enforces the core invariant: no matching pass, epoch or suppression
// evidence means transmit stays disabled.
func (o *Orchestrator) gates(ticket Ticket, evidence Evidence) []string {
	var violations []string
	if !evidence.ChainAssigned {
		violations = append(violations, fmt.Sprintf("RF chain %s is not assigned to pass %s", ticket.ChainID, ticket.PassID))
	}
	if evidence.PassPhase != passsvc.Tracking {
		violations = append(violations, fmt.Sprintf("pass phase %s does not permit transmit", evidence.PassPhase))
	}
	if evidence.DecoderEpoch < 1 {
		violations = append(violations, "pass has no decoder epoch")
	} else if evidence.DecoderEpoch != ticket.Epoch {
		violations = append(violations, fmt.Sprintf("ticket epoch %d does not match pass decoder epoch %d", ticket.Epoch, evidence.DecoderEpoch))
	}
	if evidence.AntennaOwnerPass != ticket.PassID {
		violations = append(violations, fmt.Sprintf("antenna %s is not owned by pass %s", evidence.AntennaID, ticket.PassID))
	}
	if evidence.AntennaMode != antenna.Tracking {
		violations = append(violations, fmt.Sprintf("antenna %s mode %s is not tracking", evidence.AntennaID, evidence.AntennaMode))
	}
	if evidence.InhibitOperation != ticket.ClearInhibitOperation {
		violations = append(violations, fmt.Sprintf("outstanding inhibit operation %q is not acknowledged by the ticket", evidence.InhibitOperation))
	}
	return violations
}

func (o *Orchestrator) denyLocked(ticket Ticket, action string, violations []string) {
	_, _ = o.audit.Record(audit.Event{Component: "rfsafety", Action: action, Subject: ticket.ID, Severity: audit.Warning, Fields: map[string]any{"violations": violations}})
}

func (o *Orchestrator) flushLocked() error {
	values := make([]Ticket, 0, len(o.tickets))
	for _, ticket := range o.tickets {
		values = append(values, ticket)
	}
	return store.WriteJSON(o.path, values)
}

func chainAssigned(value passsvc.Pass, chainID string) bool {
	for _, assigned := range value.RFChains {
		if assigned == chainID {
			return true
		}
	}
	return false
}
