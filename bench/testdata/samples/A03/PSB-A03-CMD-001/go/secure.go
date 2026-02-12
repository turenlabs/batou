// PSB-A03-CMD-001: Deployment script runner
// CWE: CWE-78
// Expected: (none - secure)
package main

import (
	"encoding/json"
	"net/http"
	"os/exec"
)

var allowedServices = map[string]bool{
	"api": true, "web": true, "worker": true, "scheduler": true,
}

func deploy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Service     string `json:"service"`
		Environment string `json:"environment"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.Environment != "staging" && req.Environment != "production" {
		http.Error(w, `{"error":"invalid environment"}`, http.StatusBadRequest)
		return
	}
	if !allowedServices[req.Service] {
		http.Error(w, `{"error":"unknown service"}`, http.StatusBadRequest)
		return
	}

	out, err := exec.Command("/opt/deploy/run.sh", req.Service, req.Environment).Output()
	if err != nil {
		http.Error(w, `{"error":"deployment failed"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "deployed",
		"output": string(out),
	})
}
