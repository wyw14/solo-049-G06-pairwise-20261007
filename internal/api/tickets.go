package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"orbitlink/internal/rf"
	"orbitlink/internal/rfsafety"
)

func (r *Runtime) listTickets(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]any{"items": r.Tickets.List()})
}

func (r *Runtime) requestTicket(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		PassID                string          `json:"pass_id"`
		ChainID               string          `json:"chain_id"`
		CenterHz              int64           `json:"center_hz"`
		DopplerHz             int64           `json:"doppler_hz"`
		Polarization          rf.Polarization `json:"polarization"`
		Epoch                 int64           `json:"epoch"`
		ClearInhibitOperation string          `json:"clear_inhibit_operation"`
		RequestedBy           string          `json:"requested_by"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, err)
		return
	}
	ticket, err := r.Tickets.Request(rfsafety.Request{
		PassID: input.PassID, ChainID: input.ChainID, CenterHz: input.CenterHz,
		DopplerHz: input.DopplerHz, Polarization: input.Polarization, Epoch: input.Epoch,
		ClearInhibitOperation: input.ClearInhibitOperation, RequestedBy: input.RequestedBy,
	})
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, ticket)
}

func (r *Runtime) reviewTicket(writer http.ResponseWriter, request *http.Request) {
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

func (r *Runtime) executeTicket(writer http.ResponseWriter, request *http.Request) {
	ticket, err := r.Tickets.Execute(request.Context(), chi.URLParam(request, "ticketID"))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, ticket)
}

func (r *Runtime) revokeTicket(writer http.ResponseWriter, request *http.Request) {
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
