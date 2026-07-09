//go:build !race

package scanner_test

// raceDetectorEnabled reports whether this test binary was built with the
// race detector. See racedetect_on_test.go.
const raceDetectorEnabled = false
