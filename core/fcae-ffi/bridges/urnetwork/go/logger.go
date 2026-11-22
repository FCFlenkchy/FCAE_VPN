//go:build fcae_urnetwork

package main

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	uc "github.com/urnetwork/connect"
)

// One in-process URnetwork device is supported. The atomic gate is shared by
// account workers, space/device loggers and retained SDK background workers.
var urLogLevel atomic.Uint32

type urHostLogger struct{}
type urHostVerbose struct{ level int32 }

var _ uc.Logger = urHostLogger{}
var _ uc.Verbose = urHostVerbose{}

func init() { uc.SetDefaultLogger(urHostLogger{}) }
func urSetLogLevel(level uint32) {
	if level > 4 {
		level = 0
	}
	urLogLevel.Store(level)
}
func urLogEnabled(level uint32) bool {
	return level > 0 && level <= urLogLevel.Load()
}

// Do not send SDK string/error/object arguments across the ABI. Those may
// contain JWTs, auth codes, email addresses, headers or packet payloads. Keep
// static format templates and safe scalar diagnostics, not secret values.
func urSafeArgs(args []any) []any {
	safe := make([]any, len(args))
	for i, arg := range args {
		switch v := arg.(type) {
		case bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, time.Duration:
			safe[i] = v
		default:
			safe[i] = "[redacted]"
		}
	}
	return safe
}
func urLogf(level uint32, format string, args ...any) {
	if !urLogEnabled(level) {
		return
	}
	// A no-argument "format" can be a preformatted server response. Never
	// forward it as trusted static text.
	text := "SDK event (details omitted)"
	if len(args) > 0 {
		text = fmt.Sprintf(format, urSafeArgs(args)...)
	}
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\x00", "?"), "\n", " ")
	runes := []rune(text)
	if len(runes) > 400 {
		text = string(runes[:400]) + "…"
	}
	urWriteLog(level, text)
}
func (urHostLogger) Info(args ...any)                    { urLogf(3, "SDK event: %v", urSafeArgs(args)) }
func (urHostLogger) Infof(format string, args ...any)    { urLogf(3, format, args...) }
func (urHostLogger) Warningf(format string, args ...any) { urLogf(2, format, args...) }
func (urHostLogger) Errorf(format string, args ...any)   { urLogf(1, format, args...) }
func (urHostLogger) V(level int32) uc.Verbose            { return urHostVerbose{level} }
func (v urHostVerbose) Enabled() bool                    { return v.level >= 0 && urLogEnabled(4) }
func (v urHostVerbose) Info(args ...any) {
	if v.Enabled() {
		urLogf(4, "SDK debug event: %v", urSafeArgs(args))
	}
}
func (v urHostVerbose) Infof(format string, args ...any) {
	if v.Enabled() {
		urLogf(4, format, args...)
	}
}
