//go:build race

package tlsx_test

// raceEnabled reports a -race build, whose instrumentation allocates per call and blurs byte counts (PRO-596).
const raceEnabled = true
