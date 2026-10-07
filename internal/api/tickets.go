package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (r *Runtime) listTransmitTickets(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]any{"items": r.Tickets.List()})
}

func (r *Runtime) requestTransmitTicket(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		PassID           string `json:"pass_id"`
		ChainID          string `json:"chain_id"`
		InhibitOperation string `json:"inhibit_operation"`
		RequestedBy      string `json:"requested_by"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, err)
		return
	}
	ticket, err := r.Tickets.Request(input.PassID, input.ChainID, input.InhibitOperation, input.RequestedBy)
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, ticket)
}

func (r *Runtime) reviewTransmitTicket(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		ReviewedBy string `json:"reviewed_by"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, err)
		return
	}
	ticket, err := r.Tickets.Review(chi.URLParam(request, "ticketID"), input.ReviewedBy)
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, ticket)
}

func (r *Runtime) executeTransmitTicket(writer http.ResponseWriter, request *http.Request) {
	ticket, err := r.Tickets.Execute(chi.URLParam(request, "ticketID"))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, ticket)
}

func (r *Runtime) revokeTransmitTicket(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		Reason string `json:"reason"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, err)
		return
	}
	ticket, err := r.Tickets.Revoke(request.Context(), chi.URLParam(request, "ticketID"), input.Reason)
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, ticket)
}

func (r *Runtime) enforceTransmitTickets(writer http.ResponseWriter, request *http.Request) {
	revoked, err := r.Tickets.Enforce(request.Context())
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"revoked": revoked})
}

// inhibitRFChain inhibits a chain and returns the proof that a transmit
// ticket later has to present as evidence.
func (r *Runtime) inhibitRFChain(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		OperationID string `json:"operation_id"`
	}
	if request.ContentLength > 0 {
		if err := decodeJSON(request, &input); err != nil {
			writeError(writer, err)
			return
		}
	}
	if input.OperationID == "" {
		input.OperationID = uuid.NewString()
	}
	proof, err := r.RF.Inhibit(request.Context(), chi.URLParam(request, "chainID"), input.OperationID)
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, proof)
}
