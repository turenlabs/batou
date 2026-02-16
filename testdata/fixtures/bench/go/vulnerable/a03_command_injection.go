// Source: CWE-78 - OS Command Injection in Go
// Expected: BATOU-INJ-002 (Command Injection via exec.Command)
// OWASP: A03:2021 - Injection (OS Command Injection)

package handler

import (
	"fmt"
	"net/http"
	"os/exec"
)

func PingHost(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	cmd := exec.Command("sh", "-c", "ping -c 4 "+host)
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %s", err), http.StatusInternalServerError)
		return
	}
	w.Write(output)
}

func ConvertFile(w http.ResponseWriter, r *http.Request) {
	inputPath := r.FormValue("input")
	outputFormat := r.FormValue("format")
	cmdStr := fmt.Sprintf("ffmpeg -i %s output.%s", inputPath, outputFormat)
	cmd := exec.Command("bash", "-c", cmdStr)
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, string(output), http.StatusInternalServerError)
		return
	}
	w.Write([]byte("Conversion complete"))
}
