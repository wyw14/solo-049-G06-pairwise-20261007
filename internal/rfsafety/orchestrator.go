package rfsafety

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"orbitlink/internal/antenna"
	"orbitlink/internal/audit"
	passsvc "orbitlink/internal/pass"
	"orbitlink/internal/rf"
	"orbitlink/internal/store"
)

type PassProvider interface {
	Get(id string) (passsvc.Pass, bool)
}

type ChainController interface {
	State(chainID string) (rf.State, bool)
	VerifyInhibit(chainID, operationID string) bool
	EnableTransmit(chainID string) error
	Inhibit(ctx context.Context, chainID, operationID string) (rf.InhibitProof, error)
}

type AntennaProvider interface {
	State(id string) (antenna.State, bool)
}

// Orchestrator owns the check-and-publish boundary for transmit tickets.
type Orchestrator struct {
	mu       sync.RWMutex
	path     string
	tickets  map[string]Ticket
	passes   PassProvider
	chains   ChainController
	antennas AntennaProvider
	audit    *audit.Trail
}

func NewOrchestrator(paths store.Paths, passes PassProvider, chains ChainController, antennas AntennaProvider, trail *audit.Trail) (*Orchestrator, error) {
	orchestrator := &Orchestrator{
		path: paths.Snapshot("transmit-tickets"), tickets: make(map[string]Ticket),
		passes: passes, chains: chains, antennas: antennas, audit: trail,
	}
	var values []Ticket
	found, err := store.ReadJSON(orchestrator.path, &values)
	if err != nil {
		return nil, err
	}
	if found {
		for _, value := range values {
			orchestrator.tickets[value.ID] = value
		}
	}
	return orchestrator, nil
}

// Request applies for a transmit-enable ticket. The request is only accepted
// when the pass, epoch, inhibit proof, antenna and frequency plan already
// agree; every later transition re-verifies the same evidence.
func (o *Orchestrator) Request(passID, chainID, inhibitOperation, requestedBy string) (Ticket, error) {
	if requestedBy == "" {
		return Ticket{}, fmt.Errorf("ticket requester is required")
	}
	if inhibitOperation == "" {
		return Ticket{}, fmt.Errorf("transmit inhibit operation is required as evidence")
	}
	value, found := o.passes.Get(passID)
	if !found {
		return Ticket{}, fmt.Errorf("pass %s not found", passID)
	}
	if !containsChain(value.RFChains, chainID) {
		return Ticket{}, fmt.Errorf("RF chain %s is not assigned to pass %s", chainID, passID)
	}
	evidence, err := o.collect(value, chainID, inhibitOperation)
	if err != nil {
		return Ticket{}, err
	}
	ticket := Ticket{
		ID: uuid.NewString(), PassID: passID, ChainID: chainID, AntennaID: value.AntennaID,
		Status: Requested, Evidence: evidence, RequestedBy: requestedBy, RequestedAt: time.Now().UTC(),
	}
	if err := ticket.Validate(); err != nil {
		return Ticket{}, err
	}
	if err := o.store(ticket); err != nil {
		return Ticket{}, err
	}
	_, _ = o.audit.Record(audit.Event{Component: "rfsafety", Action: "ticket.requested", Subject: ticket.ID, Fields: map[string]any{"pass_id": passID, "chain_id": chainID, "epoch": evidence.Epoch, "window_revision": evidence.WindowRevision, "inhibit_operation": inhibitOperation, "requested_by": requestedBy}})
	return ticket, nil
}

// Review is the second-operator check. The reviewer must differ from the
// requester and the evidence must still match live station state.
func (o *Orchestrator) Review(ticketID, reviewedBy string) (Ticket, error) {
	if reviewedBy == "" {
		return Ticket{}, fmt.Errorf("ticket reviewer is required")
	}
	ticket, found := o.Get(ticketID)
	if !found {
		return Ticket{}, fmt.Errorf("transmit ticket %s not found", ticketID)
	}
	if ticket.Status != Requested {
		return Ticket{}, fmt.Errorf("transmit ticket %s is %s, review requires requested", ticketID, ticket.Status)
	}
	if reviewedBy == ticket.RequestedBy {
		return Ticket{}, fmt.Errorf("transmit ticket review requires a second operator")
	}
	if err := o.verify(ticket); err != nil {
		return Ticket{}, err
	}
	ticket.Status = Reviewed
	ticket.ReviewedBy = reviewedBy
	ticket.ReviewedAt = time.Now().UTC()
	if err := o.store(ticket); err != nil {
		return Ticket{}, err
	}
	_, _ = o.audit.Record(audit.Event{Component: "rfsafety", Action: "ticket.reviewed", Subject: ticket.ID, Fields: map[string]any{"pass_id": ticket.PassID, "chain_id": ticket.ChainID, "reviewed_by": reviewedBy}})
	return ticket, nil
}

// Execute enables transmit. The full evidence gate is re-evaluated at execute
// time: without a matching pass, epoch or inhibit proof the ticket is rejected
// and the chain stays inhibited.
func (o *Orchestrator) Execute(ticketID string) (Ticket, error) {
	ticket, found := o.Get(ticketID)
	if !found {
		return Ticket{}, fmt.Errorf("transmit ticket %s not found", ticketID)
	}
	if ticket.Status != Reviewed {
		return Ticket{}, fmt.Errorf("transmit ticket %s is %s, execute requires reviewed", ticketID, ticket.Status)
	}
	if err := o.verify(ticket); err != nil {
		_, _ = o.audit.Record(audit.Event{Component: "rfsafety", Action: "ticket.execute-rejected", Subject: ticket.ID, Severity: audit.Warning, Fields: map[string]any{"pass_id": ticket.PassID, "chain_id": ticket.ChainID, "reason": err.Error()}})
		return Ticket{}, err
	}
	if err := o.chains.EnableTransmit(ticket.ChainID); err != nil {
		return Ticket{}, err
	}
	ticket.Status = Executed
	ticket.ExecutedAt = time.Now().UTC()
	if err := o.store(ticket); err != nil {
		// Transmit was enabled but the ticket did not persist: fail safe.
		_, _ = o.chains.Inhibit(context.Background(), ticket.ChainID, "execute-rollback-"+ticket.ID)
		return Ticket{}, err
	}
	_, _ = o.audit.Record(audit.Event{Component: "rfsafety", Action: "ticket.executed", Subject: ticket.ID, Fields: map[string]any{"pass_id": ticket.PassID, "chain_id": ticket.ChainID, "epoch": ticket.Evidence.Epoch, "center_hz": ticket.Evidence.Plan.CenterHz}})
	return ticket, nil
}

// Revoke withdraws a ticket. Revoking an executed ticket re-inhibits the chain
// first; the ticket only closes once the inhibit proof is confirmed.
func (o *Orchestrator) Revoke(ctx context.Context, ticketID, reason string) (Ticket, error) {
	if reason == "" {
		return Ticket{}, fmt.Errorf("revoke reason is required")
	}
	ticket, found := o.Get(ticketID)
	if !found {
		return Ticket{}, fmt.Errorf("transmit ticket %s not found", ticketID)
	}
	if ticket.Status == Revoked {
		return Ticket{}, fmt.Errorf("transmit ticket %s is already revoked", ticketID)
	}
	if ticket.Status == Executed {
		operation := "revoke-" + ticket.ID
		proof, err := o.chains.Inhibit(ctx, ticket.ChainID, operation)
		if err != nil {
			_, _ = o.audit.Record(audit.Event{Component: "rfsafety", Action: "ticket.revoke-inhibit-failed", Subject: ticket.ID, Severity: audit.Critical, Operation: operation, Fields: map[string]any{"error": err.Error()}})
			return Ticket{}, fmt.Errorf("cannot revoke transmit ticket: %w", err)
		}
		if !proof.Confirmed || !o.chains.VerifyInhibit(ticket.ChainID, operation) {
			return Ticket{}, fmt.Errorf("transmit inhibit proof for revoke of %s does not match", ticketID)
		}
	}
	return o.close(ticket, reason)
}

// Enforce sweeps every open ticket and revokes the ones whose evidence no
// longer matches live station state, e.g. after a pass leaves tracking or an
// epoch changes. Executed tickets are re-inhibited through Revoke.
func (o *Orchestrator) Enforce(ctx context.Context) ([]Ticket, error) {
	revoked := make([]Ticket, 0)
	for _, ticket := range o.List() {
		var err error
		switch ticket.Status {
		case Requested, Reviewed:
			err = o.verify(ticket)
		case Executed:
			err = o.verifyOngoing(ticket)
		default:
			continue
		}
		if err == nil {
			continue
		}
		value, revokeErr := o.Revoke(ctx, ticket.ID, "evidence no longer valid: "+err.Error())
		if revokeErr != nil {
			return revoked, revokeErr
		}
		revoked = append(revoked, value)
	}
	return revoked, nil
}

func (o *Orchestrator) Get(id string) (Ticket, bool) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	ticket, found := o.tickets[id]
	return ticket, found
}

func (o *Orchestrator) List() []Ticket {
	o.mu.RLock()
	defer o.mu.RUnlock()
	values := make([]Ticket, 0, len(o.tickets))
	for _, ticket := range o.tickets {
		values = append(values, ticket)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].RequestedAt.Before(values[j].RequestedAt) })
	return values
}

// collect snapshots the live evidence that authorizes transmit on a chain.
func (o *Orchestrator) collect(value passsvc.Pass, chainID, inhibitOperation string) (Evidence, error) {
	if value.Phase != passsvc.Tracking {
		return Evidence{}, fmt.Errorf("pass %s is %s, transmit requires tracking", value.ID, value.Phase)
	}
	if value.DecoderEpoch < 1 {
		return Evidence{}, fmt.Errorf("pass %s has no decoder epoch", value.ID)
	}
	chain, found := o.chains.State(chainID)
	if !found {
		return Evidence{}, fmt.Errorf("RF chain %s not found", chainID)
	}
	if chain.PassID != value.ID || chain.CenterHz <= 0 {
		return Evidence{}, fmt.Errorf("RF chain %s has no frequency plan for pass %s", chainID, value.ID)
	}
	if !o.chains.VerifyInhibit(chainID, inhibitOperation) {
		return Evidence{}, fmt.Errorf("RF chain %s is not inhibited under operation %s", chainID, inhibitOperation)
	}
	antennaState, found := o.antennas.State(value.AntennaID)
	if !found {
		return Evidence{}, fmt.Errorf("antenna %s not found", value.AntennaID)
	}
	if antennaState.OwnerPassID != value.ID {
		return Evidence{}, fmt.Errorf("antenna %s is not owned by pass %s", value.AntennaID, value.ID)
	}
	if antennaState.Mode != antenna.Tracking {
		return Evidence{}, fmt.Errorf("antenna %s is %s, transmit requires tracking", value.AntennaID, antennaState.Mode)
	}
	return Evidence{
		Plan:           rf.Plan{PassID: value.ID, ChainID: chainID, CenterHz: chain.CenterHz, DopplerHz: chain.DopplerHz, Polarization: chain.Polarization},
		Inhibit:        rf.InhibitProof{ChainID: chainID, Operation: inhibitOperation, Confirmed: true, ConfirmedAt: time.Now().UTC()},
		AntennaMode:    antennaState.Mode,
		PassPhase:      value.Phase,
		Epoch:          value.DecoderEpoch,
		WindowRevision: value.Window.Revision,
	}, nil
}

// verify re-evaluates a ticket's evidence against live station state before a
// transition. Any drift in pass, epoch, window revision, plan, inhibit proof
// or antenna state rejects the transition.
func (o *Orchestrator) verify(ticket Ticket) error {
	value, found := o.passes.Get(ticket.PassID)
	if !found {
		return fmt.Errorf("pass %s not found", ticket.PassID)
	}
	evidence, err := o.collect(value, ticket.ChainID, ticket.Evidence.Inhibit.Operation)
	if err != nil {
		return err
	}
	if evidence.Epoch != ticket.Evidence.Epoch {
		return fmt.Errorf("decoder epoch changed from %d to %d", ticket.Evidence.Epoch, evidence.Epoch)
	}
	if evidence.WindowRevision != ticket.Evidence.WindowRevision {
		return fmt.Errorf("pass window revision changed from %d to %d", ticket.Evidence.WindowRevision, evidence.WindowRevision)
	}
	if evidence.Plan != ticket.Evidence.Plan {
		return fmt.Errorf("frequency plan for RF chain %s changed", ticket.ChainID)
	}
	return nil
}

// verifyOngoing re-evaluates the conditions that keep an executed ticket
// authorized. The inhibit proof is consumed by the enable, so the ongoing
// check tracks the pass, epoch, plan, antenna and the enabled chain instead.
func (o *Orchestrator) verifyOngoing(ticket Ticket) error {
	value, found := o.passes.Get(ticket.PassID)
	if !found {
		return fmt.Errorf("pass %s not found", ticket.PassID)
	}
	if value.Phase != passsvc.Tracking || value.DecoderEpoch != ticket.Evidence.Epoch {
		return fmt.Errorf("pass %s no longer matches ticket epoch %d", ticket.PassID, ticket.Evidence.Epoch)
	}
	if value.Window.Revision != ticket.Evidence.WindowRevision {
		return fmt.Errorf("pass window revision changed from %d", ticket.Evidence.WindowRevision)
	}
	chain, found := o.chains.State(ticket.ChainID)
	if !found {
		return fmt.Errorf("RF chain %s not found", ticket.ChainID)
	}
	if !chain.TransmitEnabled {
		return fmt.Errorf("RF chain %s transmit is no longer enabled", ticket.ChainID)
	}
	if chain.PassID != ticket.PassID || chain.CenterHz != ticket.Evidence.Plan.CenterHz || chain.DopplerHz != ticket.Evidence.Plan.DopplerHz || chain.Polarization != ticket.Evidence.Plan.Polarization {
		return fmt.Errorf("frequency plan for RF chain %s changed", ticket.ChainID)
	}
	antennaState, found := o.antennas.State(ticket.AntennaID)
	if !found || antennaState.OwnerPassID != ticket.PassID || antennaState.Mode != antenna.Tracking {
		return fmt.Errorf("antenna %s no longer tracks pass %s", ticket.AntennaID, ticket.PassID)
	}
	return nil
}

func (o *Orchestrator) close(ticket Ticket, reason string) (Ticket, error) {
	ticket.Status = Revoked
	ticket.RevokedAt = time.Now().UTC()
	ticket.RevokeReason = reason
	if err := o.store(ticket); err != nil {
		return Ticket{}, err
	}
	_, _ = o.audit.Record(audit.Event{Component: "rfsafety", Action: "ticket.revoked", Subject: ticket.ID, Fields: map[string]any{"pass_id": ticket.PassID, "chain_id": ticket.ChainID, "reason": reason}})
	return ticket, nil
}

func (o *Orchestrator) store(ticket Ticket) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.tickets[ticket.ID] = ticket
	return o.flushLocked()
}

func (o *Orchestrator) flushLocked() error {
	values := make([]Ticket, 0, len(o.tickets))
	for _, ticket := range o.tickets {
		values = append(values, ticket)
	}
	return store.WriteJSON(o.path, values)
}

func containsChain(chains []string, chainID string) bool {
	for _, id := range chains {
		if id == chainID {
			return true
		}
	}
	return false
}
