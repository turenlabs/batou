package findings

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// RunCLI handles the `batou findings` subcommand.
// Returns exit code: 0 success, 1 error.
func RunCLI(args []string) int {
	batouDir, err := FindRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	store, err := Open(batouDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	// Parse flags
	var (
		showSummary    bool
		showSuppressed bool
		showAll        bool
		showJSON       bool
	)
	for _, arg := range args {
		switch arg {
		case "--summary", "-s":
			showSummary = true
		case "--suppressed":
			showSuppressed = true
		case "--all", "-a":
			showAll = true
		case "--json":
			showJSON = true
		case "--help", "-h":
			printUsage()
			return 0
		}
	}

	if showJSON {
		return outputJSON(store, showAll, showSuppressed)
	}

	if showSummary {
		return outputSummary(store)
	}

	if showSuppressed {
		records := store.Suppressed()
		if len(records) == 0 {
			fmt.Println("No suppressed findings.")
			return 0
		}
		fmt.Printf("Suppressed findings (%d):\n\n", len(records))
		for _, r := range records {
			printRecord(r)
		}
		return 0
	}

	if showAll {
		records := store.All()
		if len(records) == 0 {
			fmt.Println("No findings recorded yet.")
			return 0
		}
		counts := store.CountByStatus()
		fmt.Printf("All findings: %d active, %d suppressed, %d resolved\n\n",
			counts[StatusActive], counts[StatusSuppressed], counts[StatusResolved])
		for _, r := range records {
			printRecord(r)
		}
		return 0
	}

	// Default: show active findings
	records := store.Active()
	if len(records) == 0 {
		fmt.Println("No active findings. Code looks clean!")
		return 0
	}
	fmt.Printf("Active findings (%d):\n\n", len(records))
	for _, r := range records {
		printRecord(r)
	}
	return 0
}

func outputJSON(store *Store, showAll, showSuppressed bool) int {
	var records []*Record
	switch {
	case showAll:
		records = store.All()
	case showSuppressed:
		records = store.Suppressed()
	default:
		records = store.Active()
	}

	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	fmt.Println(string(data))
	return 0
}

func outputSummary(store *Store) int {
	counts := store.CountByStatus()
	summary := store.Summary()

	total := counts[StatusActive] + counts[StatusSuppressed] + counts[StatusResolved]
	if total == 0 {
		fmt.Println("No findings recorded yet.")
		return 0
	}

	fmt.Println("=== Batou Findings Summary ===")
	fmt.Println()
	fmt.Printf("  Active:     %d\n", counts[StatusActive])
	fmt.Printf("  Suppressed: %d\n", counts[StatusSuppressed])
	fmt.Printf("  Resolved:   %d\n", counts[StatusResolved])
	fmt.Printf("  Total:      %d\n", total)

	if len(summary) > 0 {
		fmt.Println()
		fmt.Println("  Active by severity:")
		for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
			if n, ok := summary[sev]; ok {
				fmt.Printf("    %-8s  %d\n", sev, n)
			}
		}
	}
	fmt.Println()
	return 0
}

func printRecord(r *Record) {
	loc := r.FilePath
	if r.LineNumber > 0 {
		loc = fmt.Sprintf("%s:%d", r.FilePath, r.LineNumber)
	}

	status := ""
	switch r.Status {
	case StatusSuppressed:
		status = " [suppressed]"
	case StatusResolved:
		status = " [resolved]"
	}

	fmt.Printf("  [%s] %s%s\n", r.SeverityLabel, r.RuleID, status)
	fmt.Printf("    %s\n", r.Title)
	fmt.Printf("    %s\n", loc)
	if r.SuppressReason != "" {
		fmt.Printf("    Reason: %s\n", r.SuppressReason)
	}
	fmt.Printf("    First seen: %s | Count: %d\n", formatTime(r.FirstSeen), r.Count)
	fmt.Println()
}

func formatTime(ts string) string {
	// Trim to date only for compact display
	if idx := strings.IndexByte(ts, 'T'); idx > 0 {
		return ts[:idx]
	}
	return ts
}

func printUsage() {
	fmt.Println(`Usage: batou findings [flags]

Show security findings tracked across hook invocations.

Flags:
  --summary, -s    Show counts by severity and status
  --suppressed     Show findings suppressed via batou:ignore
  --all, -a        Show all findings (active + suppressed + resolved)
  --json           Output as JSON (combinable with other flags)
  --help, -h       Show this help`)
}
