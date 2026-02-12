// PSB-A03-CMD-001: Deployment script runner
// CWE: CWE-78
// Expected: GTSS-INJ-005, GTSS-INJ-006
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
)

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

	cmd := fmt.Sprintf("/opt/deploy/run.sh %s %s", req.Service, req.Environment)
	out, err := exec.Command("sh", "-c", cmd).Output()
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
