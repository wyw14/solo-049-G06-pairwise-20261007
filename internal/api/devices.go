package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"orbitlink/internal/rf"
	"orbitlink/internal/satellite"
	"orbitlink/internal/weather"
)

func (r *Runtime) listAntennas(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]any{"items": r.Antennas.List()})
}
func (r *Runtime) listRFChains(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]any{"items": r.RF.List()})
}

func (r *Runtime) applyRFPlan(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		PassID       string           `json:"pass_id"`
		CenterHz     int64            `json:"center_hz"`
		DopplerHz    int64            `json:"doppler_hz"`
		Polarization rf.Polarization  `json:"polarization"`
		DopplerSteps []rf.DopplerStep `json:"doppler_steps"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, err)
		return
	}
	if len(input.DopplerSteps) == 0 {
		now := time.Now().UTC()
		input.DopplerSteps = []rf.DopplerStep{{At: now.Add(-time.Second), OffsetHz: input.DopplerHz}, {At: now.Add(time.Second), OffsetHz: input.DopplerHz}}
	}
	if err := rf.ValidateDopplerPlan(input.CenterHz, input.DopplerSteps); err != nil {
		writeError(writer, err)
		return
	}
	state, err := r.RF.Apply(rf.Plan{PassID: input.PassID, ChainID: chi.URLParam(request, "chainID"), CenterHz: input.CenterHz, DopplerHz: rf.InterpolateDoppler(input.DopplerSteps, time.Now().UTC()), Polarization: input.Polarization})
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, state)
}

func (r *Runtime) executeDuePointing(writer http.ResponseWriter, _ *http.Request) {
	commands, err := r.Executor.RunDue(time.Now().UTC())
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"executed": commands})
}

func (r *Runtime) importEphemeris(writer http.ResponseWriter, request *http.Request) {
	var input satellite.Ephemeris
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, err)
		return
	}
	value, err := r.Ephemerides.Import(input)
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, value)
}

func (r *Runtime) stowAntenna(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		PassID              string  `json:"pass_id"`
		ChainID             string  `json:"chain_id"`
		GustMetersPerSecond float64 `json:"gust_meters_per_second"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeError(writer, err)
		return
	}
	result, err := r.Weather.Handle(request.Context(), weather.WindSample{StationID: "orbitlink", GustMetersPerSecond: input.GustMetersPerSecond, ObservedAt: time.Now().UTC()}, input.PassID, chi.URLParam(request, "antennaID"), input.ChainID)
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}
