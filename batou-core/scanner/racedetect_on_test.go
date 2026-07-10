//go:build race

package scanner_test

// raceDetectorEnabled reports whether this test binary was built with the
// race detector. Timing-sensitive guards (e.g. asserting the scanner's
// 10-second rule timeout never fires on a synthesized corpus) must skip
// under -race: the detector inflates rule wall-time 5-10x on CI hardware,
// so the timeout fires for instrumentation reasons, not scan degradation.
const raceDetectorEnabled = true
