package vulnerable

import (
	"net/http"
	"os"
	"syscall"
)

// VULN: Low-level process execution with user-controlled binary path.
// syscall.Exec and os.StartProcess bypass os/exec safety wrappers.

func HandleSyscallExec(w http.ResponseWriter, r *http.Request) {
	binary := r.FormValue("binary")
	args := []string{binary, "-version"}
	syscall.Exec(binary, args, os.Environ())
}

func HandleStartProcess(w http.ResponseWriter, r *http.Request) {
	prog := r.FormValue("program")
	os.StartProcess(prog, []string{prog}, &os.ProcAttr{})
}
