package scanner

import (
	"testing"
	"time"
)

// TestEffectiveScanTimeout pins the BATOU_SCAN_TIMEOUT override that lets the
// -race large-file perf gate (TestLargeFileScansWithoutTimeout) use a budget
// scaled for the race detector's wall-clock inflation. Production never sets the
// var, so the default must stay the 10s scanTimeout; a bad/zero/negative value
// must fall back to that default rather than silently disabling the cap.
func TestEffectiveScanTimeout(t *testing.T) {
	cases := []struct {
		name string
		set  bool
		val  string
		want time.Duration
	}{
		{"unset -> default 10s", false, "", scanTimeout},
		{"valid override 30s", true, "30s", 30 * time.Second},
		{"valid override 60s", true, "60s", 60 * time.Second},
		{"valid override sub-second", true, "500ms", 500 * time.Millisecond},
		{"invalid -> default", true, "not-a-duration", scanTimeout},
		{"empty -> default", true, "", scanTimeout},
		{"zero -> default", true, "0s", scanTimeout},
		{"negative -> default", true, "-5s", scanTimeout},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.set {
				t.Setenv("BATOU_SCAN_TIMEOUT", c.val)
			} else {
				// Ensure no ambient value leaks in.
				t.Setenv("BATOU_SCAN_TIMEOUT", "")
			}
			if got := effectiveScanTimeout(); got != c.want {
				t.Errorf("effectiveScanTimeout() = %v, want %v", got, c.want)
			}
		})
	}
	// The production default is and must remain 10s.
	if scanTimeout != 10*time.Second {
		t.Errorf("scanTimeout default changed to %v; production cap must stay 10s", scanTimeout)
	}
}
