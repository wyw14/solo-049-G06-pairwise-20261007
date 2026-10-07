package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"orbitlink/internal/receiver"
	"orbitlink/internal/rf"
	"orbitlink/internal/rfsafety"
)

func TestTransmitTicketAPIFlow(t *testing.T) {
	runtime := newTestRuntime(t)
	value := runtime.Passes.List()[0]
	if _, err := runtime.RF.Apply(rf.Plan{PassID: value.ID, ChainID: "RF-01", CenterHz: 2_245_000_000, DopplerHz: 12_000, Polarization: rf.RightCircular}); err != nil {
		t.Fatal(err)
	}
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
	if decision, err := runtime.Passes.AcceptDiversity(value.ID, results); err != nil || !decision.Ready {
		t.Fatalf("diversity did not converge: %#v %v", decision, err)
	}
	commands := runtime.Commands.List(value.ID)
	if len(commands) == 0 {
		t.Fatal("no pointing commands queued for the pass")
	}
	if err := runtime.Executor.Execute(commands[0]); err != nil {
		t.Fatal(err)
	}
	router, err := NewRouter(runtime)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(router)
	defer server.Close()

	// Transmit enable without a ticket is no longer served.
	if response := requestJSON(t, server.Client(), "POST", server.URL+"/api/rf-chains/RF-01/transmit", `{}`); response.StatusCode != http.StatusNotFound {
		t.Fatalf("direct transmit endpoint returned %d, expected 404", response.StatusCode)
	}

	// Inhibit the chain and keep the proof as ticket evidence.
	response := requestJSON(t, server.Client(), "POST", server.URL+"/api/rf-chains/RF-01/inhibit", `{"operation_id":"op-7"}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("inhibit returned %d", response.StatusCode)
	}
	var proof rf.InhibitProof
	decodeBody(t, response, &proof)
	if !proof.Confirmed || proof.Operation != "op-7" {
		t.Fatalf("inhibit proof not confirmed: %#v", proof)
	}

	// A ticket without matching inhibit evidence is refused.
	response = requestJSON(t, server.Client(), "POST", server.URL+"/api/transmit-tickets", fmt.Sprintf(`{"pass_id":%q,"chain_id":"RF-01","inhibit_operation":"op-other","requested_by":"operator-a"}`, value.ID))
	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("ticket with wrong inhibit evidence returned %d", response.StatusCode)
	}
	_ = response.Body.Close()

	// Request, review and execute the ticket.
	response = requestJSON(t, server.Client(), "POST", server.URL+"/api/transmit-tickets", fmt.Sprintf(`{"pass_id":%q,"chain_id":"RF-01","inhibit_operation":"op-7","requested_by":"operator-a"}`, value.ID))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("ticket request returned %d", response.StatusCode)
	}
	var ticket rfsafety.Ticket
	decodeBody(t, response, &ticket)
	if ticket.Status != rfsafety.Requested || ticket.Evidence.Epoch != 7 {
		t.Fatalf("unexpected ticket: %#v", ticket)
	}
	response = requestJSON(t, server.Client(), "POST", server.URL+"/api/transmit-tickets/"+ticket.ID+"/review", `{"reviewed_by":"operator-a"}`)
	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("self-review returned %d", response.StatusCode)
	}
	_ = response.Body.Close()
	response = requestJSON(t, server.Client(), "POST", server.URL+"/api/transmit-tickets/"+ticket.ID+"/review", `{"reviewed_by":"operator-b"}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("review returned %d", response.StatusCode)
	}
	_ = response.Body.Close()
	response = requestJSON(t, server.Client(), "POST", server.URL+"/api/transmit-tickets/"+ticket.ID+"/execute", `{}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("execute returned %d", response.StatusCode)
	}
	decodeBody(t, response, &ticket)
	if ticket.Status != rfsafety.Executed {
		t.Fatalf("ticket is %s, expected executed", ticket.Status)
	}
	if state, _ := runtime.RF.State("RF-01"); !state.TransmitEnabled {
		t.Fatal("executed ticket did not enable transmit")
	}

	// Revoking the executed ticket re-inhibits the chain.
	response = requestJSON(t, server.Client(), "POST", server.URL+"/api/transmit-tickets/"+ticket.ID+"/revoke", `{"reason":"pass complete"}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("revoke returned %d", response.StatusCode)
	}
	decodeBody(t, response, &ticket)
	if ticket.Status != rfsafety.Revoked {
		t.Fatalf("ticket is %s, expected revoked", ticket.Status)
	}
	if !runtime.RF.VerifyInhibit("RF-01", "revoke-"+ticket.ID) {
		t.Fatal("revoked ticket did not re-inhibit the chain")
	}
}
