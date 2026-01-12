package zone

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDefaultZoneFileData tests default zone file data generation
func TestDefaultZoneFileData(t *testing.T) {
	tests := []struct {
		name string
		zone string
	}{
		{"simple zone", "example.com."},
		{"subdomain zone", "sub.example.com."},
		{"single label", "localhost."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := DefaultZoneFileData(tt.zone)

			if data == nil {
				t.Fatal("DefaultZoneFileData() returned nil")
			}

			// Verify zone is set correctly
			if data.Zone != tt.zone {
				t.Errorf("Zone = %q, want %q", data.Zone, tt.zone)
			}

			// Verify TTL is set
			if data.TTL == 0 {
				t.Error("TTL should not be zero")
			}

			// Verify NS is constructed correctly
			expectedNS := "ns1." + tt.zone
			if data.NS != expectedNS {
				t.Errorf("NS = %q, want %q", data.NS, expectedNS)
			}

			// Verify email is constructed correctly
			expectedEmail := "hostmaster." + tt.zone
			if data.Email != expectedEmail {
				t.Errorf("Email = %q, want %q", data.Email, expectedEmail)
			}

			// Verify serial is in YYYYMMDDNN format
			now := time.Now()
			minSerial := uint32(now.Year()*1000000 + int(now.Month())*10000 + now.Day()*100)
			if data.Serial < minSerial {
				t.Errorf("Serial = %d, should be at least %d", data.Serial, minSerial)
			}

			// Verify refresh, retry, expire, minimum are set
			if data.Refresh == 0 {
				t.Error("Refresh should not be zero")
			}
			if data.Retry == 0 {
				t.Error("Retry should not be zero")
			}
			if data.Expire == 0 {
				t.Error("Expire should not be zero")
			}
			if data.Minimum == 0 {
				t.Error("Minimum should not be zero")
			}

			// Verify NS records are set
			if len(data.NSRecords) == 0 {
				t.Error("NSRecords should not be empty")
			}
		})
	}
}

// TestGenerateZoneFile tests zone file content generation
func TestGenerateZoneFile(t *testing.T) {
	data := &ZoneFileData{
		Zone:    "example.com.",
		TTL:     3600,
		NS:      "ns1.example.com.",
		Email:   "hostmaster.example.com.",
		Serial:  2024010100,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minimum: 3600,
		NSRecords: []string{
			"@ IN NS ns1.example.com.",
			"@ IN NS ns2.example.com.",
		},
		Defaults: []string{
			"@ IN CAA 0 issue \"letsencrypt.org\"",
		},
	}

	content, err := GenerateZoneFile(data)
	if err != nil {
		t.Fatalf("GenerateZoneFile() error = %v", err)
	}

	// Verify content contains expected elements
	expectedContents := []string{
		"$ORIGIN example.com.",
		"$TTL 3600",
		"@ IN SOA ns1.example.com. hostmaster.example.com.",
		"2024010100", // serial
		"@ IN NS ns1.example.com.",
		"@ IN NS ns2.example.com.",
		"@ IN CAA 0 issue \"letsencrypt.org\"",
	}

	for _, expected := range expectedContents {
		if !strings.Contains(content, expected) {
			t.Errorf("Zone file content should contain %q, got:\n%s", expected, content)
		}
	}
}

// TestWriteZoneFile tests zone file writing
func TestWriteZoneFile(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("write new zone file", func(t *testing.T) {
		path := filepath.Join(tmpDir, "example.com.db")
		data := DefaultZoneFileData("example.com.")

		err := WriteZoneFile(path, data, "", "")
		if err != nil {
			t.Fatalf("WriteZoneFile() error = %v", err)
		}

		// Verify file exists
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Error("Zone file was not created")
		}

		// Verify content
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("Failed to read zone file: %v", err)
		}

		if !strings.Contains(string(content), "example.com.") {
			t.Error("Zone file should contain zone name")
		}
	})

	t.Run("overwrite existing zone file", func(t *testing.T) {
		path := filepath.Join(tmpDir, "overwrite.db")

		// Write initial file
		if err := os.WriteFile(path, []byte("old content"), 0644); err != nil {
			t.Fatalf("Failed to create initial file: %v", err)
		}

		data := DefaultZoneFileData("new.example.com.")
		err := WriteZoneFile(path, data, "", "")
		if err != nil {
			t.Fatalf("WriteZoneFile() error = %v", err)
		}

		content, _ := os.ReadFile(path)
		if strings.Contains(string(content), "old content") {
			t.Error("Zone file should be overwritten")
		}
		if !strings.Contains(string(content), "new.example.com.") {
			t.Error("Zone file should contain new zone name")
		}
	})

	t.Run("create with nested directory", func(t *testing.T) {
		path := filepath.Join(tmpDir, "nested", "deep", "zone.db")
		data := DefaultZoneFileData("nested.example.com.")

		// This should fail because parent directories don't exist
		err := WriteZoneFile(path, data, "", "")
		if err == nil {
			t.Error("WriteZoneFile() should fail for non-existent parent directory")
		}
	})
}

// TestRemoveZoneFile tests zone file removal
func TestRemoveZoneFile(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("remove existing file", func(t *testing.T) {
		path := filepath.Join(tmpDir, "toremove.db")
		if err := os.WriteFile(path, []byte("zone content"), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		err := RemoveZoneFile(path)
		if err != nil {
			t.Fatalf("RemoveZoneFile() error = %v", err)
		}

		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Error("Zone file should be removed")
		}
	})

	t.Run("remove non-existent file", func(t *testing.T) {
		path := filepath.Join(tmpDir, "nonexistent.db")

		err := RemoveZoneFile(path)
		if err != nil {
			t.Errorf("RemoveZoneFile() should not error for non-existent file: %v", err)
		}
	})
}

// TestZoneFileExists tests zone file existence checking
func TestZoneFileExists(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("file exists", func(t *testing.T) {
		path := filepath.Join(tmpDir, "exists.db")
		if err := os.WriteFile(path, []byte("content"), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		if !ZoneFileExists(path) {
			t.Error("ZoneFileExists() should return true for existing file")
		}
	})

	t.Run("file does not exist", func(t *testing.T) {
		path := filepath.Join(tmpDir, "notexists.db")

		if ZoneFileExists(path) {
			t.Error("ZoneFileExists() should return false for non-existent file")
		}
	})

	t.Run("directory instead of file", func(t *testing.T) {
		path := filepath.Join(tmpDir, "directory")
		if err := os.Mkdir(path, 0755); err != nil {
			t.Fatalf("Failed to create test directory: %v", err)
		}

		// Directories also "exist" in the filesystem sense
		if !ZoneFileExists(path) {
			t.Error("ZoneFileExists() returns true for directories too")
		}
	})
}

// TestBumpSerial tests SOA serial number incrementing
func TestBumpSerial(t *testing.T) {
	now := time.Now()
	todaySerial := uint32(now.Year()*1000000 + int(now.Month())*10000 + now.Day()*100)

	tests := []struct {
		name          string
		currentSerial uint32
		wantMin       uint32
		wantMax       uint32
	}{
		{
			name:          "old serial - get today's date",
			currentSerial: 2020010100,
			wantMin:       todaySerial,
			wantMax:       todaySerial,
		},
		{
			name:          "today's serial - increment",
			currentSerial: todaySerial,
			wantMin:       todaySerial + 1,
			wantMax:       todaySerial + 1,
		},
		{
			name:          "future serial - increment",
			currentSerial: todaySerial + 10,
			wantMin:       todaySerial + 11,
			wantMax:       todaySerial + 11,
		},
		{
			name:          "maximum revision for today",
			currentSerial: todaySerial + 99,
			wantMin:       todaySerial + 100,
			wantMax:       todaySerial + 100,
		},
		{
			name:          "zero serial",
			currentSerial: 0,
			wantMin:       todaySerial,
			wantMax:       todaySerial,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BumpSerial(tt.currentSerial)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("BumpSerial(%d) = %d, want between %d and %d",
					tt.currentSerial, got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

// TestBoolToYesNo tests boolean to yes/no conversion
func TestBoolToYesNo(t *testing.T) {
	tests := []struct {
		input bool
		want  string
	}{
		{true, "yes"},
		{false, "no"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := boolToYesNo(tt.input)
			if got != tt.want {
				t.Errorf("boolToYesNo(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestBufWriter tests the buffer writer implementation
func TestBufWriter(t *testing.T) {
	var buf []byte
	writer := &bufWriter{buf: &buf}

	// Write some data
	n, err := writer.Write([]byte("hello "))
	if err != nil {
		t.Fatalf("bufWriter.Write() error = %v", err)
	}
	if n != 6 {
		t.Errorf("bufWriter.Write() returned %d, want 6", n)
	}

	n, err = writer.Write([]byte("world"))
	if err != nil {
		t.Fatalf("bufWriter.Write() error = %v", err)
	}
	if n != 5 {
		t.Errorf("bufWriter.Write() returned %d, want 5", n)
	}

	if string(buf) != "hello world" {
		t.Errorf("buf = %q, want %q", string(buf), "hello world")
	}
}
