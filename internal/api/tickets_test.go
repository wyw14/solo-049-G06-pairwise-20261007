package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"orbitlink/internal/antenna"
	passsvc "orbitlink/internal/pass"
	"orbitlink/internal/receiver"
	"orbitlink/internal/rfsafety"
)

func TestTransmitTicketLifecycleOverHTTP(t *testing.T) {
	runtime := newTestRuntime(t)
	value := drivePassToTracking(t, runtime)
	router, err := NewRouter(runtime)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(router)
	defer server.Close()
	client := server.Client()

	response := requestJSON(t, client, http.MethodPost, server.URL+"/api/rf-chains/RF-01/transmit", `{}`)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("raw transmit endpoint must be gone, got %d", response.StatusCode)
	}
	_ = response.Body.Close()

	response = requestJSON(t, client, http.MethodPost, server.URL+"/api/rf-tickets",
		fmt.Sprintf(`{"pass_id":%q,"chain_id":"RF-01","center_hz":2245000000,"doppler_hz":12000,"polarization":"RHCP","epoch":7,"requested_by":"op-alpha"}`, value.ID))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("ticket request returned %d", response.StatusCode)
	}
	var ticket rfsafety.Ticket
	decodeBody(t, response, &ticket)
	if ticket.Stage != rfsafety.StageRequested {
		t.Fatalf("unexpected stage %s", ticket.Stage)
	}

	response = requestJSON(t, client, http.MethodPost, server.URL+"/api/rf-tickets/"+ticket.ID+"/review", `{"reviewed_by":"op-alpha"}`)
	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("self-review must be rejected, got %d", response.StatusCode)
	}
	_ = response.Body.Close()

	response = requestJSON(t, client, http.MethodPost, server.URL+"/api/rf-tickets/"+ticket.ID+"/review", `{"reviewed_by":"op-bravo"}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("review returned %d", response.StatusCode)
	}
	_ = response.Body.Close()

	response = requestJSON(t, client, http.MethodPost, server.URL+"/api/rf-tickets/"+ticket.ID+"/execute", `{}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("execute returned %d", response.StatusCode)
	}
	_ = response.Body.Close()
	state, found := runtime.RF.State("RF-01")
	if !found || !state.TransmitEnabled || state.CenterHz != 2_245_000_000 {
		t.Fatalf("executed ticket did not enable transmit with the plan: %#v", state)
	}

	response = requestJSON(t, client, http.MethodPost, server.URL+"/api/rf-tickets/"+ticket.ID+"/revoke", `{"reason":"pass complete"}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("revoke returned %d", response.StatusCode)
	}
	_ = response.Body.Close()
	state, _ = runtime.RF.State("RF-01")
	if state.TransmitEnabled || state.InhibitOperation != "revoke:"+ticket.ID {
		t.Fatalf("revoke must verifiably inhibit the chain: %#v", state)
	}
}

func TestTransmitTicketGatesOverHTTP(t *testing.T) {
	runtime := newTestRuntime(t)
	value := drivePassToTracking(t, runtime)
	router, err := NewRouter(runtime)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(router)
	defer server.Close()
	client := server.Client()

	response := requestJSON(t, client, http.MethodPost, server.URL+"/api/rf-tickets",
		fmt.Sprintf(`{"pass_id":%q,"chain_id":"RF-01","center_hz":2245000000,"epoch":99,"requested_by":"op-alpha"}`, value.ID))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("ticket request returned %d", response.StatusCode)
	}
	var ticket rfsafety.Ticket
	decodeBody(t, response, &ticket)

	response = requestJSON(t, client, http.MethodPost, server.URL+"/api/rf-tickets/"+ticket.ID+"/review", `{"reviewed_by":"op-bravo"}`)
	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("epoch mismatch must block review, got %d", response.StatusCode)
	}
	_ = response.Body.Close()
	if state, _ := runtime.RF.State("RF-01"); state.TransmitEnabled {
		t.Fatal("transmit must stay disabled when the epoch does not match")
	}
}

// drivePassToTracking moves the seeded pass into the tracking phase with a
// decoder epoch and puts its antenna into tracking mode, so transmit tickets
// have satisfiable safety evidence.
func drivePassToTracking(t *testing.T, runtime *Runtime) passsvc.Pass {
	t.Helper()
	value := runtime.Passes.List()[0]
	attempt, err := runtime.Attempts.Begin(value.ID, "RF-01")
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Passes.BeginAcquisition(value.ID, attempt.ID); err != nil {
		t.Fatal(err)
	}
	results := []receiver.AcquisitionResult{
		{PassID: value.ID, AttemptID: attempt.ID, ChainID: "RF-01", Locked: true, Synced: true, Epoch: 7},
		{PassID: value.ID, AttemptID: attempt.ID, ChainID: "RF-02", Locked: true, Synced: true, Epoch: 7},
	}
	decision, err := runtime.Passes.AcceptDiversity(value.ID, results)
	if err != nil || !decision.Ready {
		t.Fatalf("diversity did not converge: %#v %v", decision, err)
	}
	now := time.Now().UTC()
	points := []antenna.TrackPoint{
		{At: now.Add(-2 * time.Second), Azimuth: 130, Elevation: 25},
		{At: now.Add(-time.Second), Azimuth: 135, Elevation: 28},
	}
	commands, err := antenna.BuildCommands(value.ID, value.AntennaID, value.Window.Revision, points)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Commands.Replace(value.ID, value.Window.Revision, commands); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Executor.RunDue(now); err != nil {
		t.Fatal(err)
	}
	state, found := runtime.Antennas.State(value.AntennaID)
	if !found || state.Mode != antenna.Tracking || state.OwnerPassID != value.ID {
		t.Fatalf("antenna is not tracking for the pass: %#v", state)
	}
	value, found = runtime.Passes.Get(value.ID)
	if !found || value.Phase != passsvc.Tracking || value.DecoderEpoch != 7 {
		t.Fatalf("pass is not tracking with epoch 7: %#v", value)
	}
	return value
}
