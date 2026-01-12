package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNewResult tests result creation
func TestNewResult(t *testing.T) {
	result := NewResult("zone:create", "req-12345")

	if !result.OK {
		t.Error("NewResult() should set OK to true")
	}
	if result.Op != "zone:create" {
		t.Errorf("NewResult() Op = %q, want %q", result.Op, "zone:create")
	}
	if result.RequestID != "req-12345" {
		t.Errorf("NewResult() RequestID = %q, want %q", result.RequestID, "req-12345")
	}
	if result.Changes == nil {
		t.Error("NewResult() should initialize Changes slice")
	}
	if result.Warnings == nil {
		t.Error("NewResult() should initialize Warnings slice")
	}
	if result.Error != nil {
		t.Error("NewResult() should not set Error")
	}
}

// TestNewErrorResult tests error result creation
func TestNewErrorResult(t *testing.T) {
	result := NewErrorResult("rrset:upsert", "req-67890", ExitValidationError, "invalid TTL", "TTL 30 is below minimum 60")

	if result.OK {
		t.Error("NewErrorResult() should set OK to false")
	}
	if result.Op != "rrset:upsert" {
		t.Errorf("NewErrorResult() Op = %q, want %q", result.Op, "rrset:upsert")
	}
	if result.RequestID != "req-67890" {
		t.Errorf("NewErrorResult() RequestID = %q, want %q", result.RequestID, "req-67890")
	}
	if result.Error == nil {
		t.Fatal("NewErrorResult() should set Error")
	}
	if result.Error.Code != ExitValidationError {
		t.Errorf("NewErrorResult() Error.Code = %d, want %d", result.Error.Code, ExitValidationError)
	}
	if result.Error.Message != "invalid TTL" {
		t.Errorf("NewErrorResult() Error.Message = %q, want %q", result.Error.Message, "invalid TTL")
	}
	if result.Error.Details != "TTL 30 is below minimum 60" {
		t.Errorf("NewErrorResult() Error.Details = %q, want %q", result.Error.Details, "TTL 30 is below minimum 60")
	}
}

// TestResultAddChange tests adding changes to a result
func TestResultAddChange(t *testing.T) {
	result := NewResult("zone:create", "req-123")

	result.AddChange("zone_file_created")
	result.AddChange("zone_added")
	result.AddChange("catalog_updated")

	if len(result.Changes) != 3 {
		t.Fatalf("AddChange() Changes length = %d, want 3", len(result.Changes))
	}

	expected := []string{"zone_file_created", "zone_added", "catalog_updated"}
	for i, change := range expected {
		if result.Changes[i] != change {
			t.Errorf("Changes[%d] = %q, want %q", i, result.Changes[i], change)
		}
	}
}

// TestResultAddWarning tests adding warnings to a result
func TestResultAddWarning(t *testing.T) {
	result := NewResult("zone:delete", "req-456")

	result.AddWarning("zone_file_cleanup_failed")
	result.AddWarning("catalog_already_removed")

	if len(result.Warnings) != 2 {
		t.Fatalf("AddWarning() Warnings length = %d, want 2", len(result.Warnings))
	}

	expected := []string{"zone_file_cleanup_failed", "catalog_already_removed"}
	for i, warning := range expected {
		if result.Warnings[i] != warning {
			t.Errorf("Warnings[%d] = %q, want %q", i, result.Warnings[i], warning)
		}
	}
}

// TestResultOutput tests JSON output serialization
func TestResultOutput(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	result := NewResult("rrset:get", "req-789")
	result.Zone = "example.com."
	result.AddChange("record_found")

	err := result.Output()
	if err != nil {
		t.Fatalf("Output() error = %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Failed to close pipe: %v", err)
	}
	os.Stdout = oldStdout

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatalf("Failed to read from pipe: %v", err)
	}
	output := buf.String()

	// Verify JSON structure
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("Output() produced invalid JSON: %v", err)
	}

	if parsed["ok"] != true {
		t.Errorf("Output() ok = %v, want true", parsed["ok"])
	}
	if parsed["op"] != "rrset:get" {
		t.Errorf("Output() op = %v, want rrset:get", parsed["op"])
	}
	if parsed["request_id"] != "req-789" {
		t.Errorf("Output() request_id = %v, want req-789", parsed["request_id"])
	}
	if parsed["zone"] != "example.com." {
		t.Errorf("Output() zone = %v, want example.com.", parsed["zone"])
	}
}

// TestNewLogger tests logger creation
func TestNewLogger(t *testing.T) {
	var buf bytes.Buffer

	t.Run("basic logger creation", func(t *testing.T) {
		logger := NewLogger(&buf, "", false)
		if logger == nil {
			t.Fatal("NewLogger() returned nil")
		}
		if logger.RequestID() == "" {
			t.Error("NewLogger() should generate a request ID")
		}
	})

	t.Run("request ID is UUID format", func(t *testing.T) {
		logger := NewLogger(&buf, "", false)
		reqID := logger.RequestID()
		// UUID format: 8-4-4-4-12 = 36 chars with hyphens
		if len(reqID) != 36 {
			t.Errorf("RequestID length = %d, want 36 (UUID format)", len(reqID))
		}
		parts := strings.Split(reqID, "-")
		if len(parts) != 5 {
			t.Errorf("RequestID parts = %d, want 5 (UUID format)", len(parts))
		}
	})

	t.Run("with audit file path", func(t *testing.T) {
		tmpDir := t.TempDir()
		auditPath := filepath.Join(tmpDir, "audit.jsonl")

		logger := NewLogger(&buf, auditPath, false)
		defer func() {
			if err := logger.Close(); err != nil {
				t.Errorf("Failed to close logger: %v", err)
			}
		}()

		if logger == nil {
			t.Fatal("NewLogger() returned nil")
		}
	})
}

// TestLoggerChaining tests method chaining for logger configuration
func TestLoggerChaining(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, "", false)

	// Test method chaining
	result := logger.WithOp("zone:create").WithZone("example.com.").WithActor("admin")

	if result != logger {
		t.Error("Method chaining should return the same logger instance")
	}
}

// TestLoggerLevels tests different log levels
func TestLoggerLevels(t *testing.T) {
	tests := []struct {
		name   string
		logFn  func(*Logger, string)
		level  string
	}{
		{"Info", (*Logger).Info, "INFO"},
		{"Warn", (*Logger).Warn, "WARN"},
		{"Error", (*Logger).Error, "ERROR"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := NewLogger(&buf, "", false)

			tt.logFn(logger, "test message")

			output := buf.String()
			if !strings.Contains(output, tt.level) {
				t.Errorf("Log output should contain level %q, got: %s", tt.level, output)
			}
			if !strings.Contains(output, "test message") {
				t.Errorf("Log output should contain message, got: %s", output)
			}
		})
	}
}

// TestLoggerDebug tests debug logging with verbose flag
func TestLoggerDebug(t *testing.T) {
	t.Run("debug suppressed when verbose is false", func(t *testing.T) {
		var buf bytes.Buffer
		logger := NewLogger(&buf, "", false)
		logger.SetVerbose(false)

		logger.Debug("debug message")

		if buf.Len() > 0 {
			t.Error("Debug should not output when verbose is false")
		}
	})

	t.Run("debug outputs when verbose is true", func(t *testing.T) {
		var buf bytes.Buffer
		logger := NewLogger(&buf, "", false)
		logger.SetVerbose(true)

		logger.Debug("debug message")

		output := buf.String()
		if !strings.Contains(output, "DEBUG") {
			t.Errorf("Debug output should contain DEBUG level, got: %s", output)
		}
		if !strings.Contains(output, "debug message") {
			t.Errorf("Debug output should contain message, got: %s", output)
		}
	})
}

// TestLoggerWriteAudit tests audit log writing
func TestLoggerWriteAudit(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")

	var buf bytes.Buffer
	logger := NewLogger(&buf, auditPath, false)
	logger.WithOp("zone:create").WithZone("example.com.")

	result := NewResult("zone:create", logger.RequestID())
	result.Zone = "example.com."
	result.AddChange("zone_created")

	logger.WriteAudit(result)
	if err := logger.Close(); err != nil {
		t.Fatalf("Failed to close logger: %v", err)
	}

	// Read audit file
	content, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("Failed to read audit file: %v", err)
	}

	if len(content) == 0 {
		t.Error("Audit file should not be empty")
	}

	// Parse JSONL entry
	var entry map[string]interface{}
	if err := json.Unmarshal(content, &entry); err != nil {
		t.Fatalf("Audit entry is not valid JSON: %v", err)
	}

	if entry["ok"] != true {
		t.Errorf("Audit entry ok = %v, want true", entry["ok"])
	}
}

// TestLoggerClose tests closing the logger
func TestLoggerClose(t *testing.T) {
	t.Run("close without audit file", func(t *testing.T) {
		var buf bytes.Buffer
		logger := NewLogger(&buf, "", false)

		err := logger.Close()
		if err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})

	t.Run("close with audit file", func(t *testing.T) {
		tmpDir := t.TempDir()
		auditPath := filepath.Join(tmpDir, "audit.jsonl")

		var buf bytes.Buffer
		logger := NewLogger(&buf, auditPath, false)

		err := logger.Close()
		if err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
}

// TestExitCodes tests that exit codes are defined correctly
func TestExitCodes(t *testing.T) {
	tests := []struct {
		name  string
		code  int
		value int
	}{
		{"ExitSuccess", ExitSuccess, 0},
		{"ExitValidationError", ExitValidationError, 2},
		{"ExitPreconditionFail", ExitPreconditionFail, 3},
		{"ExitRuntimeFailure", ExitRuntimeFailure, 4},
		{"ExitConflictUnsafe", ExitConflictUnsafe, 5},
		{"ExitInternalError", ExitInternalError, 6},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.code != tt.value {
				t.Errorf("%s = %d, want %d", tt.name, tt.code, tt.value)
			}
		})
	}
}

// TestLoggerJSONFormat tests that log entries are valid JSON
func TestLoggerJSONFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&buf, "", false)
	logger.WithOp("test:op").WithZone("example.com.")

	logger.Info("test message")

	output := buf.String()

	// Parse the JSON (log output includes newline from log.Println)
	output = strings.TrimSpace(output)

	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(output), &entry); err != nil {
		t.Fatalf("Log entry is not valid JSON: %v\nOutput: %s", err, output)
	}

	// Verify required fields
	requiredFields := []string{"time", "level", "request_id", "msg"}
	for _, field := range requiredFields {
		if _, ok := entry[field]; !ok {
			t.Errorf("Log entry missing required field: %s", field)
		}
	}
}
