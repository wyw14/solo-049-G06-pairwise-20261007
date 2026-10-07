package rfsafety

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"orbitlink/internal/antenna"
	"orbitlink/internal/audit"
	passsvc "orbitlink/internal/pass"
	"orbitlink/internal/rf"
	"orbitlink/internal/store"
)

type fakePassSource struct {
	value passsvc.Pass
	found bool
}

func (f *fakePassSource) Get(id string) (passsvc.Pass, bool) {
	if !f.found || f.value.ID != id {
		return passsvc.Pass{}, false
	}
	return f.value, true
}

type fakeAntennaSource struct {
	value antenna.State
	found bool
}

func (f *fakeAntennaSource) State(id string) (antenna.State, bool) {
	if !f.found || f.value.ID != id {
		return antenna.State{}, false
	}
	return f.value, true
}

type fakeRadio struct {
	state       rf.State
	found       bool
	applied     []rf.Plan
	enabled     []string
	inhibited   []string
	inhibitFail bool
}

func (f *fakeRadio) Apply(plan rf.Plan) (rf.State, error) {
	f.applied = append(f.applied, plan)
	f.state.PassID = plan.PassID
	f.state.CenterHz = plan.CenterHz
	return f.state, nil
}

func (f *fakeRadio) EnableTransmit(chainID string) error {
	f.enabled = append(f.enabled, chainID)
	f.state.TransmitEnabled = true
	f.state.InhibitOperation = ""
	return nil
}

func (f *fakeRadio) Inhibit(_ context.Context, chainID, operationID string) (rf.InhibitProof, error) {
	if f.inhibitFail {
		return rf.InhibitProof{}, fmt.Errorf("inhibit hardware fault")
	}
	f.inhibited = append(f.inhibited, operationID)
	f.state.TransmitEnabled = false
	f.state.InhibitOperation = operationID
	return rf.InhibitProof{ChainID: chainID, Operation: operationID, Confirmed: true, ConfirmedAt: time.Now().UTC()}, nil
}

func (f *fakeRadio) VerifyInhibit(_, operationID string) bool {
	return !f.state.TransmitEnabled && f.state.InhibitOperation == operationID
}

func (f *fakeRadio) State(chainID string) (rf.State, bool) {
	if !f.found || f.state.ChainID != chainID {
		return rf.State{}, false
	}
	return f.state, true
}

type rig struct {
	orchestrator *Orchestrator
	passes       *fakePassSource
	antennas     *fakeAntennaSource
	radio        *fakeRadio
	root         string
	trail        *audit.Trail
}

func newRig(t *testing.T) rig {
	t.Helper()
	root := t.TempDir()
	trail := audit.NewTrail(store.NewAppendLog(store.NewPaths(root)))
	passes := &fakePassSource{found: true, value: passsvc.Pass{
		ID: "PASS-1", SatelliteID: "SAT-A12", AntennaID: "ANT-01",
		RFChains: []string{"RF-01"}, RequiredReceiverChains: []string{"RF-01"},
		Window: passsvc.Window{AOS: time.Now().Add(-time.Minute), LOS: time.Now().Add(time.Minute), Revision: 3},
		Phase:  passsvc.Tracking, DecoderEpoch: 7,
		OwnerStation: "north", OwnerGeneration: 1,
	}}
	antennas := &fakeAntennaSource{found: true, value: antenna.State{
		ID: "ANT-01", Mode: antenna.Tracking, Azimuth: 140, Elevation: 35,
		OwnerPassID: "PASS-1", OwnerGeneration: 2,
	}}
	radio := &fakeRadio{found: true, state: rf.State{ChainID: "RF-01", Polarization: rf.RightCircular}}
	orchestrator, err := NewOrchestrator(store.NewPaths(root), trail, passes, antennas, radio, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rig{orchestrator: orchestrator, passes: passes, antennas: antennas, radio: radio, root: root, trail: trail}
}

func (r rig) request(t *testing.T) Ticket {
	t.Helper()
	ticket, err := r.orchestrator.Request(Request{
		PassID: "PASS-1", ChainID: "RF-01", CenterHz: 2_245_000_000, DopplerHz: 12_000,
		Polarization: rf.RightCircular, Epoch: 7, RequestedBy: "op-alpha",
	})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return ticket
}

func TestTicketLifecycleRequestReviewExecuteRevoke(t *testing.T) {
	r := newRig(t)
	ticket := r.request(t)
	if ticket.Stage != StageRequested || ticket.RequestEvidence.PassPhase != passsvc.Tracking {
		t.Fatalf("unexpected ticket after request: %#v", ticket)
	}
	if _, err := r.orchestrator.Review(ticket.ID, "op-alpha"); err == nil {
		t.Fatal("self-review must be rejected")
	}
	reviewed, err := r.orchestrator.Review(ticket.ID, "op-bravo")
	if err != nil {
		t.Fatalf("review: %v", err)
	}
	if reviewed.Stage != StageReviewed || reviewed.ReviewEvidence == nil {
		t.Fatalf("unexpected ticket after review: %#v", reviewed)
	}
	executed, err := r.orchestrator.Execute(context.Background(), ticket.ID)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if executed.Stage != StageExecuted {
		t.Fatalf("unexpected stage %s", executed.Stage)
	}
	if len(r.radio.enabled) != 1 || r.radio.enabled[0] != "RF-01" {
		t.Fatalf("transmit was not enabled exactly once: %v", r.radio.enabled)
	}
	if len(r.radio.applied) != 1 || r.radio.applied[0].CenterHz != 2_245_000_000 {
		t.Fatalf("frequency plan was not applied: %#v", r.radio.applied)
	}
	revoked, err := r.orchestrator.Revoke(context.Background(), ticket.ID, "pass complete")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revoked.Stage != StageRevoked || revoked.RevokeInhibitOperation != "revoke:"+ticket.ID {
		t.Fatalf("unexpected ticket after revoke: %#v", revoked)
	}
	if len(r.radio.inhibited) != 1 || r.radio.inhibited[0] != "revoke:"+ticket.ID {
		t.Fatalf("revoke did not inhibit the chain: %v", r.radio.inhibited)
	}
	if r.radio.state.TransmitEnabled {
		t.Fatal("chain must not radiate after revoke")
	}
}

func TestRequestRejectsStaticViolations(t *testing.T) {
	r := newRig(t)
	if _, err := r.orchestrator.Request(Request{PassID: "PASS-1", ChainID: "RF-01", CenterHz: 2_245_000_000, Epoch: 0, RequestedBy: "op-alpha"}); err == nil {
		t.Fatal("epoch zero must be rejected")
	}
	if _, err := r.orchestrator.Request(Request{PassID: "PASS-404", ChainID: "RF-01", CenterHz: 2_245_000_000, Epoch: 7, RequestedBy: "op-alpha"}); err == nil {
		t.Fatal("unknown pass must be rejected")
	}
	if _, err := r.orchestrator.Request(Request{PassID: "PASS-1", ChainID: "RF-99", CenterHz: 2_245_000_000, Epoch: 7, RequestedBy: "op-alpha"}); err == nil {
		t.Fatal("chain outside the pass plan must be rejected")
	}
	r.request(t)
	if _, err := r.orchestrator.Request(Request{PassID: "PASS-1", ChainID: "RF-01", CenterHz: 2_245_000_000, Epoch: 7, RequestedBy: "op-alpha"}); err == nil {
		t.Fatal("a second open ticket for the same chain must be rejected")
	}
}

func TestReviewGatesBlockUnsafeEvidence(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(r rig)
		want   string
	}{
		{"pass not tracking", func(r rig) { r.passes.value.Phase = passsvc.Acquiring }, "does not permit transmit"},
		{"pass without epoch", func(r rig) { r.passes.value.DecoderEpoch = 0 }, "no decoder epoch"},
		{"epoch mismatch", func(r rig) { r.passes.value.DecoderEpoch = 9 }, "does not match"},
		{"antenna not owned", func(r rig) { r.antennas.value.OwnerPassID = "PASS-2" }, "is not owned"},
		{"antenna not tracking", func(r rig) { r.antennas.value.Mode = antenna.Idle }, "is not tracking"},
		{"inhibit not acknowledged", func(r rig) { r.radio.state.InhibitOperation = "wx-stow-1" }, "not acknowledged"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			tc.mutate(r)
			ticket := r.request(t)
			_, err := r.orchestrator.Review(ticket.ID, "op-bravo")
			var gate *GateError
			if !errors.As(err, &gate) {
				t.Fatalf("expected GateError, got %v", err)
			}
			if !strings.Contains(gate.Error(), tc.want) {
				t.Fatalf("violation %q does not mention %q", gate.Error(), tc.want)
			}
			if len(r.radio.enabled) != 0 {
				t.Fatal("transmit must stay disabled when gates fail")
			}
		})
	}
}

func TestAcknowledgedInhibitEvidenceAllowsEnable(t *testing.T) {
	r := newRig(t)
	r.radio.state.InhibitOperation = "wx-stow-1"
	ticket, err := r.orchestrator.Request(Request{
		PassID: "PASS-1", ChainID: "RF-01", CenterHz: 2_245_000_000, Epoch: 7,
		RequestedBy: "op-alpha", ClearInhibitOperation: "wx-stow-1",
	})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if _, err := r.orchestrator.Review(ticket.ID, "op-bravo"); err != nil {
		t.Fatalf("review with acknowledged inhibit: %v", err)
	}
	if _, err := r.orchestrator.Execute(context.Background(), ticket.ID); err != nil {
		t.Fatalf("execute with acknowledged inhibit: %v", err)
	}
	if len(r.radio.enabled) != 1 {
		t.Fatal("acknowledged inhibit evidence should permit transmit")
	}
}

func TestExecuteRejectsEvidenceDrift(t *testing.T) {
	r := newRig(t)
	ticket := r.request(t)
	if _, err := r.orchestrator.Review(ticket.ID, "op-bravo"); err != nil {
		t.Fatalf("review: %v", err)
	}
	r.passes.value.Window.Revision = 4
	if _, err := r.orchestrator.Execute(context.Background(), ticket.ID); err == nil {
		t.Fatal("execute must refuse drifted evidence")
	}
	current, _ := r.orchestrator.Get(ticket.ID)
	if current.Stage != StageRequested || current.ReviewEvidence != nil {
		t.Fatalf("stale review must return the ticket to requested: %#v", current)
	}
	if len(r.radio.enabled) != 0 {
		t.Fatal("transmit must stay disabled when evidence drifted")
	}
}

func TestExecuteRejectsGateViolation(t *testing.T) {
	r := newRig(t)
	ticket := r.request(t)
	if _, err := r.orchestrator.Review(ticket.ID, "op-bravo"); err != nil {
		t.Fatalf("review: %v", err)
	}
	r.passes.value.DecoderEpoch = 8
	_, err := r.orchestrator.Execute(context.Background(), ticket.ID)
	var gate *GateError
	if !errors.As(err, &gate) {
		t.Fatalf("expected GateError, got %v", err)
	}
	current, _ := r.orchestrator.Get(ticket.ID)
	if current.Stage != StageReviewed {
		t.Fatalf("gate denial keeps the ticket reviewed for a fresh attempt: %s", current.Stage)
	}
	if len(r.radio.enabled) != 0 {
		t.Fatal("transmit must stay disabled when the epoch no longer matches")
	}
}

func TestRevokeRequiresConfirmedInhibit(t *testing.T) {
	r := newRig(t)
	ticket := r.request(t)
	if _, err := r.orchestrator.Review(ticket.ID, "op-bravo"); err != nil {
		t.Fatalf("review: %v", err)
	}
	if _, err := r.orchestrator.Execute(context.Background(), ticket.ID); err != nil {
		t.Fatalf("execute: %v", err)
	}
	r.radio.inhibitFail = true
	if _, err := r.orchestrator.Revoke(context.Background(), ticket.ID, "pass complete"); err == nil {
		t.Fatal("revoke must fail when the inhibit cannot be confirmed")
	}
	current, _ := r.orchestrator.Get(ticket.ID)
	if current.Stage != StageExecuted {
		t.Fatalf("ticket must stay executed while suppression is unconfirmed: %s", current.Stage)
	}
}

func TestTicketsSurviveReload(t *testing.T) {
	r := newRig(t)
	ticket := r.request(t)
	reloaded, err := NewOrchestrator(store.NewPaths(r.root), r.trail, r.passes, r.antennas, r.radio, nil)
	if err != nil {
		t.Fatal(err)
	}
	restored, found := reloaded.Get(ticket.ID)
	if !found {
		t.Fatal("ticket did not survive a state reload")
	}
	if restored.Stage != StageRequested || restored.Epoch != 7 || restored.Plan.CenterHz != 2_245_000_000 {
		t.Fatalf("restored ticket mismatch: %#v", restored)
	}
}
