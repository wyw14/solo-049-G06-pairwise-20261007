package rfsafety

import (
	"context"
	"fmt"
	"testing"
	"time"

	"orbitlink/internal/antenna"
	"orbitlink/internal/audit"
	passsvc "orbitlink/internal/pass"
	"orbitlink/internal/rf"
	"orbitlink/internal/store"
)

type fakePasses struct {
	value passsvc.Pass
}

func (f *fakePasses) Get(id string) (passsvc.Pass, bool) {
	if f.value.ID == id {
		return f.value, true
	}
	return passsvc.Pass{}, false
}

type fakeChains struct {
	states map[string]rf.State
}

func (f *fakeChains) State(id string) (rf.State, bool) {
	state, found := f.states[id]
	return state, found
}

func (f *fakeChains) VerifyInhibit(id, operation string) bool {
	state, found := f.states[id]
	return found && !state.TransmitEnabled && state.InhibitOperation == operation
}

func (f *fakeChains) EnableTransmit(id string) error {
	state, found := f.states[id]
	if !found {
		return fmt.Errorf("RF chain %s not found", id)
	}
	state.TransmitEnabled = true
	state.InhibitOperation = ""
	f.states[id] = state
	return nil
}

func (f *fakeChains) Inhibit(_ context.Context, id, operation string) (rf.InhibitProof, error) {
	state, found := f.states[id]
	if !found {
		return rf.InhibitProof{}, fmt.Errorf("RF chain %s not found", id)
	}
	state.TransmitEnabled = false
	state.InhibitOperation = operation
	f.states[id] = state
	return rf.InhibitProof{ChainID: id, Operation: operation, Confirmed: true, ConfirmedAt: time.Now().UTC()}, nil
}

type fakeAntennas struct {
	states map[string]antenna.State
}

func (f *fakeAntennas) State(id string) (antenna.State, bool) {
	state, found := f.states[id]
	return state, found
}

type fixture struct {
	orchestrator *Orchestrator
	paths        store.Paths
	trail        *audit.Trail
	passes       *fakePasses
	chains       *fakeChains
	antennas     *fakeAntennas
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	paths := store.NewPaths(t.TempDir())
	trail := audit.NewTrail(store.NewAppendLog(paths))
	passes := &fakePasses{value: passsvc.Pass{
		ID: "pass-1", SatelliteID: "SAT-A12", AntennaID: "ANT-1",
		RFChains: []string{"RF-1"}, RequiredReceiverChains: []string{"RF-1"},
		Window: passsvc.Window{AOS: time.Now().UTC(), LOS: time.Now().UTC().Add(time.Hour), Revision: 3},
		Phase:  passsvc.Tracking, DecoderEpoch: 7,
		OwnerStation: "north", OwnerGeneration: 1,
	}}
	chains := &fakeChains{states: map[string]rf.State{
		"RF-1": {ChainID: "RF-1", PassID: "pass-1", CenterHz: 2_245_000_000, DopplerHz: 12_000, Polarization: rf.RightCircular, InhibitOperation: "op-1"},
	}}
	antennas := &fakeAntennas{states: map[string]antenna.State{
		"ANT-1": {ID: "ANT-1", Mode: antenna.Tracking, OwnerPassID: "pass-1", OwnerGeneration: 1},
	}}
	orchestrator, err := NewOrchestrator(paths, passes, chains, antennas, trail)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{orchestrator: orchestrator, paths: paths, trail: trail, passes: passes, chains: chains, antennas: antennas}
}

func (f fixture) reviewedTicket(t *testing.T) Ticket {
	t.Helper()
	ticket, err := f.orchestrator.Request("pass-1", "RF-1", "op-1", "operator-a")
	if err != nil {
		t.Fatal(err)
	}
	ticket, err = f.orchestrator.Review(ticket.ID, "operator-b")
	if err != nil {
		t.Fatal(err)
	}
	return ticket
}

func TestTicketLifecycleEnablesTransmit(t *testing.T) {
	f := newFixture(t)
	ticket := f.reviewedTicket(t)
	ticket, err := f.orchestrator.Execute(ticket.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ticket.Status != Executed {
		t.Fatalf("ticket is %s, expected executed", ticket.Status)
	}
	if state, _ := f.chains.State("RF-1"); !state.TransmitEnabled {
		t.Fatal("executed ticket did not enable transmit")
	}
}

func TestRequestRejectedWithoutInhibitEvidence(t *testing.T) {
	f := newFixture(t)
	if _, err := f.orchestrator.Request("pass-1", "RF-1", "", "operator-a"); err == nil {
		t.Fatal("request without inhibit operation unexpectedly succeeded")
	}
	if _, err := f.orchestrator.Request("pass-1", "RF-1", "op-unknown", "operator-a"); err == nil {
		t.Fatal("request with unverified inhibit operation unexpectedly succeeded")
	}
}

func TestRequestRejectedWithoutMatchingPass(t *testing.T) {
	f := newFixture(t)
	if _, err := f.orchestrator.Request("pass-missing", "RF-1", "op-1", "operator-a"); err == nil {
		t.Fatal("request for unknown pass unexpectedly succeeded")
	}
	f.passes.value.Phase = passsvc.Planned
	if _, err := f.orchestrator.Request("pass-1", "RF-1", "op-1", "operator-a"); err == nil {
		t.Fatal("request outside tracking phase unexpectedly succeeded")
	}
	f.passes.value.Phase = passsvc.Tracking
	f.passes.value.DecoderEpoch = 0
	if _, err := f.orchestrator.Request("pass-1", "RF-1", "op-1", "operator-a"); err == nil {
		t.Fatal("request without decoder epoch unexpectedly succeeded")
	}
}

func TestRequestRejectedWithoutPlanOrAntenna(t *testing.T) {
	f := newFixture(t)
	f.chains.states["RF-1"] = rf.State{ChainID: "RF-1", InhibitOperation: "op-1"}
	if _, err := f.orchestrator.Request("pass-1", "RF-1", "op-1", "operator-a"); err == nil {
		t.Fatal("request without frequency plan unexpectedly succeeded")
	}
	f = newFixture(t)
	f.antennas.states["ANT-1"] = antenna.State{ID: "ANT-1", Mode: antenna.Idle, OwnerPassID: "pass-1"}
	if _, err := f.orchestrator.Request("pass-1", "RF-1", "op-1", "operator-a"); err == nil {
		t.Fatal("request with idle antenna unexpectedly succeeded")
	}
}

func TestReviewRequiresSecondOperator(t *testing.T) {
	f := newFixture(t)
	ticket, err := f.orchestrator.Request("pass-1", "RF-1", "op-1", "operator-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.orchestrator.Review(ticket.ID, "operator-a"); err == nil {
		t.Fatal("requester reviewed their own ticket")
	}
	if _, err := f.orchestrator.Execute(ticket.ID); err == nil {
		t.Fatal("unreviewed ticket executed")
	}
}

func TestExecuteRejectedWhenEpochChanges(t *testing.T) {
	f := newFixture(t)
	ticket := f.reviewedTicket(t)
	f.passes.value.DecoderEpoch = 9
	if _, err := f.orchestrator.Execute(ticket.ID); err == nil {
		t.Fatal("execute succeeded after decoder epoch changed")
	}
	if state, _ := f.chains.State("RF-1"); state.TransmitEnabled {
		t.Fatal("transmit enabled despite epoch mismatch")
	}
}

func TestExecuteRejectedWhenPlanDrifts(t *testing.T) {
	f := newFixture(t)
	ticket := f.reviewedTicket(t)
	chain := f.chains.states["RF-1"]
	chain.CenterHz = 2_250_000_000
	f.chains.states["RF-1"] = chain
	if _, err := f.orchestrator.Execute(ticket.ID); err == nil {
		t.Fatal("execute succeeded after frequency plan drifted")
	}
}

func TestExecuteRejectedWhenInhibitConsumed(t *testing.T) {
	f := newFixture(t)
	ticket := f.reviewedTicket(t)
	if err := f.chains.EnableTransmit("RF-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.orchestrator.Execute(ticket.ID); err == nil {
		t.Fatal("execute succeeded after inhibit evidence was consumed")
	}
}

func TestRevokeExecutedTicketReinhibits(t *testing.T) {
	f := newFixture(t)
	ticket := f.reviewedTicket(t)
	if _, err := f.orchestrator.Execute(ticket.ID); err != nil {
		t.Fatal(err)
	}
	ticket, err := f.orchestrator.Revoke(context.Background(), ticket.ID, "operator request")
	if err != nil {
		t.Fatal(err)
	}
	if ticket.Status != Revoked {
		t.Fatalf("ticket is %s, expected revoked", ticket.Status)
	}
	if !f.chains.VerifyInhibit("RF-1", "revoke-"+ticket.ID) {
		t.Fatal("revoked executed ticket did not re-inhibit the chain")
	}
}

func TestEnforceRevokesStaleTickets(t *testing.T) {
	f := newFixture(t)
	ticket := f.reviewedTicket(t)
	if _, err := f.orchestrator.Execute(ticket.ID); err != nil {
		t.Fatal(err)
	}
	f.passes.value.Phase = passsvc.Completed
	revoked, err := f.orchestrator.Enforce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 1 || revoked[0].ID != ticket.ID {
		t.Fatalf("enforce revoked %v, expected ticket %s", revoked, ticket.ID)
	}
	if state, _ := f.chains.State("RF-1"); state.TransmitEnabled {
		t.Fatal("transmit stayed enabled after the pass left tracking")
	}
}

func TestTicketsPersistAcrossRestart(t *testing.T) {
	f := newFixture(t)
	ticket := f.reviewedTicket(t)
	reloaded, err := NewOrchestrator(f.paths, f.passes, f.chains, f.antennas, f.trail)
	if err != nil {
		t.Fatal(err)
	}
	restored, found := reloaded.Get(ticket.ID)
	if !found {
		t.Fatal("reviewed ticket did not survive a restart")
	}
	if restored.Status != Reviewed || restored.Evidence.Epoch != 7 || restored.Evidence.Inhibit.Operation != "op-1" {
		t.Fatalf("restored ticket drifted: %#v", restored)
	}
	if _, err := reloaded.Execute(ticket.ID); err != nil {
		t.Fatalf("restored ticket did not execute: %v", err)
	}
}
