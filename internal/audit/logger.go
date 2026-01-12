package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/gofrs/uuid/v5"
)

// Logger provides structured logging for dnsctl operations
type Logger struct {
	requestID string
	actor     string
	op        string
	zone      string
	out       io.Writer
	auditFile *os.File
	verbose   bool
}

// NewLogger creates a new logger with a generated request ID
func NewLogger(out io.Writer, auditPath string, includeActor bool) *Logger {
	reqID := uuid.Must(uuid.NewV4()).String()
	l := &Logger{
		requestID: reqID,
		out:       out,
		verbose:   false,
	}

	// Try to open audit file if path specified
	if auditPath != "" {
		f, err := os.OpenFile(auditPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0640)
		if err == nil {
			l.auditFile = f
		}
		// Don't fail if audit file can't be opened - it's optional per spec
	}

	// Extract actor from environment if requested
	if includeActor {
		l.actor = os.Getenv("SSH_ORIGINAL_COMMAND")
		// Could also extract from SSH key comment mapping
	}

	return l
}

// WithOp sets the operation name for logging context
func (l *Logger) WithOp(op string) *Logger {
	l.op = op
	return l
}

// WithZone sets the zone for logging context
func (l *Logger) WithZone(zone string) *Logger {
	l.zone = zone
	return l
}

// WithActor sets the actor for logging context
func (l *Logger) WithActor(actor string) *Logger {
	l.actor = actor
	return l
}

// SetVerbose enables verbose logging
func (l *Logger) SetVerbose(v bool) {
	l.verbose = v
}

// Info logs an informational message to stderr
func (l *Logger) Info(msg string) {
	l.log("INFO", msg)
}

// Warn logs a warning message to stderr
func (l *Logger) Warn(msg string) {
	l.log("WARN", msg)
}

// Error logs an error message to stderr
func (l *Logger) Error(msg string) {
	l.log("ERROR", msg)
}

// Debug logs a debug message to stderr (only if verbose)
func (l *Logger) Debug(msg string) {
	if l.verbose {
		l.log("DEBUG", msg)
	}
}

// Log writes a structured log entry to stderr with the specified level and message.
func (l *Logger) Log(level, msg string) {
	l.log(level, msg)
}

// log writes a structured log entry to stderr
func (l *Logger) log(level, msg string) {
	entry := struct {
		Time      string `json:"time"`
		Level     string `json:"level"`
		RequestID string `json:"request_id"`
		Op        string `json:"op,omitempty"`
		Zone      string `json:"zone,omitempty"`
		Actor     string `json:"actor,omitempty"`
		Message   string `json:"msg"`
	}{
		Time:      time.Now().UTC().Format(time.RFC3339),
		Level:     level,
		RequestID: l.requestID,
		Op:        l.op,
		Zone:      l.zone,
		Actor:     l.actor,
		Message:   msg,
	}

	// Use the stdlib logger for stderr output
	log.SetOutput(l.out)
	log.SetFlags(0) // We'll format our own JSON
	data, _ := json.Marshal(entry)
	log.Println(string(data))
}

// RequestID returns the request ID for this operation
func (l *Logger) RequestID() string {
	return l.requestID
}

// WriteAudit writes an audit entry to the audit log file (JSONL format)
func (l *Logger) WriteAudit(result *Result) {
	if l.auditFile == nil {
		return
	}

	entry := struct {
		Time      string   `json:"time"`
		RequestID string   `json:"request_id"`
		Op        string   `json:"op"`
		Zone      string   `json:"zone,omitempty"`
		Actor     string   `json:"actor,omitempty"`
		OK        bool     `json:"ok"`
		Changes   []string `json:"changes,omitempty"`
		Warnings  []string `json:"warnings,omitempty"`
		Error     *Error   `json:"error,omitempty"`
		Duration  int64    `json:"duration_ms,omitempty"`
	}{
		Time:      time.Now().UTC().Format(time.RFC3339),
		RequestID: l.requestID,
		Op:        l.op,
		Zone:      l.zone,
		Actor:     l.actor,
		OK:        result.OK,
		Changes:   result.Changes,
		Warnings:  result.Warnings,
		Error:     result.Error,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	_, _ = l.auditFile.Write(append(data, '\n'))
}

// Close closes the audit file if open
func (l *Logger) Close() error {
	if l.auditFile != nil {
		return l.auditFile.Close()
	}
	return nil
}

// Result represents the structured JSON output per spec 7.1/14.3
type Result struct {
	OK        bool     `json:"ok"`
	Op        string   `json:"op"`
	RequestID string   `json:"request_id"`
	Zone      string   `json:"zone,omitempty"`
	Changes   []string `json:"changes,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
	Error     *Error   `json:"error,omitempty"`
}

// Error represents an error in the JSON output
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// NewResult creates a new successful result
func NewResult(op string, requestID string) *Result {
	return &Result{
		OK:        true,
		Op:        op,
		RequestID: requestID,
		Changes:   []string{},
		Warnings:  []string{},
	}
}

// NewErrorResult creates a new error result
func NewErrorResult(op string, requestID string, exitCode int, message string, details string) *Result {
	return &Result{
		OK:        false,
		Op:        op,
		RequestID: requestID,
		Error: &Error{
			Code:    exitCode,
			Message: message,
			Details: details,
		},
	}
}

// Output writes the result as JSON to stdout
func (r *Result) Output() error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

// AddChange records a change made during the operation
func (r *Result) AddChange(change string) {
	if r.Changes == nil {
		r.Changes = []string{}
	}
	r.Changes = append(r.Changes, change)
}

// AddWarning records a warning during the operation
func (r *Result) AddWarning(warning string) {
	if r.Warnings == nil {
		r.Warnings = []string{}
	}
	r.Warnings = append(r.Warnings, warning)
}
