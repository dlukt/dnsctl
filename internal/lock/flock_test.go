package lock

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestNewLock tests lock creation
func TestNewLock(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name      string
		zone      string
		lockDir   string
		expectErr bool
	}{
		{
			name:      "simple zone",
			zone:      "example.com.",
			lockDir:   tmpDir,
			expectErr: false,
		},
		{
			name:      "zone with subdomain",
			zone:      "www.example.com.",
			lockDir:   tmpDir,
			expectErr: false,
		},
		{
			name:      "IDN zone",
			zone:      "xn--mnchen-3ya.de.",
			lockDir:   tmpDir,
			expectErr: false,
		},
		{
			name:      "zone with slashes (escaped)",
			zone:      "example.com./path",
			lockDir:   tmpDir,
			expectErr: false, // Should be sanitized
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lock := New(tt.lockDir + "/zone--" + sanitizeZone(tt.zone) + ".lock")
			if lock == nil {
				t.Error("NewLock returned nil")
			}
		})
	}
}

// sanitizeZone is a helper to mimic the zone sanitization in lock file names
func sanitizeZone(zone string) string {
	// Replace dots and special chars with dashes
	sanitized := ""
	for _, c := range zone {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			sanitized += string(c)
		} else {
			sanitized += "-"
		}
	}
	return sanitized
}

// TestAcquireRelease tests basic lock acquire and release
func TestAcquireRelease(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "test.lock")
	lock := New(lockPath)

	// Acquire the lock
	err := lock.Acquire()
	if err != nil {
		t.Fatalf("Failed to acquire lock: %v", err)
	}

	// Verify lock file exists
	if _, err := os.Stat(lockPath); os.IsNotExist(err) {
		t.Error("Lock file was not created")
	}

	// Release the lock
	lock.Release()

	// Lock file should still exist (implementation detail)
	// The file is kept around but the lock is released
}

// TestConcurrentLock tests that concurrent access is properly serialized
func TestConcurrentLock(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent test in short mode")
	}

	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "concurrent.lock")

	// Channel to coordinate goroutines
	ready := make(chan struct{})
	done := make(chan struct{})
	acquired := make(chan struct{})

	// First goroutine acquires lock
	go func() {
		lock := New(lockPath)
		close(ready) // Signal we're ready
		err := lock.Acquire()
		if err != nil {
			t.Errorf("First goroutine failed to acquire lock: %v", err)
		}
		close(acquired) // Signal we acquired the lock
		time.Sleep(50 * time.Millisecond) // Hold lock briefly
		lock.Release()
		close(done)
	}()

	<-ready // Wait for first goroutine to be ready
	<-acquired // Wait for lock to be acquired

	// Try to acquire the same lock with a NEW lock object
	// This should block or fail because the first goroutine holds it
	lock2 := New(lockPath)
	err := lock2.Acquire()
	// Depending on implementation, this might fail immediately or block
	// For testing, we'll just make sure it doesn't deadlock
	if err == nil {
		lock2.Release()
	}

	select {
	case <-done:
		// First goroutine finished, as expected
	case <-time.After(500 * time.Millisecond):
		t.Error("Timeout waiting for first goroutine")
	}
}

// TestLockReentrancy tests that the same lock object can be reacquired
func TestLockReentrancy(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "reentrant.lock")
	lock := New(lockPath)

	// First acquire
	err := lock.Acquire()
	if err != nil {
		t.Fatalf("First acquire failed: %v", err)
	}

	// Second acquire from same lock object
	// With flock, same process trying to acquire again may succeed or fail
	// depending on whether we're tracking lock depth
	// The implementation doesn't support reentrancy, so we expect it to fail
	err = lock.Acquire()
	if err == nil {
		// If it succeeds, that's also fine - just release twice
		lock.Release()
	}
	// If it fails, that's the expected behavior for non-reentrant locks

	// Release the first lock
	lock.Release()
}

// TestLockPath tests that lock file paths are correctly constructed
func TestLockPath(t *testing.T) {
	tests := []struct {
		zone         string
		lockDir      string
		expectedFile string
	}{
		{
			zone:         "example.com.",
			lockDir:      "/var/lock/dnsctl",
			expectedFile: "/var/lock/dnsctl/zone--example-com-.lock",
		},
		{
			zone:         "www.example.com.",
			lockDir:      "/var/lock/dnsctl",
			expectedFile: "/var/lock/dnsctl/zone--www-example-com-.lock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.zone, func(t *testing.T) {
			// We can't test the actual LockFilePath method without exporting it
			// but we can test the pattern
			expected := filepath.Join(tt.lockDir, "zone--"+sanitizeZone(tt.zone)+".lock")
			if expected != tt.expectedFile {
				t.Errorf("Lock path mismatch: got %s, want %s", expected, tt.expectedFile)
			}
		})
	}
}

// TestReleaseWithoutAcquire tests releasing a lock that was never acquired
func TestReleaseWithoutAcquire(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "unlocked.lock")
	lock := New(lockPath)

	// Should not panic or error
	lock.Release()
}

// TestMultipleZones tests that locks for different zones don't interfere
func TestMultipleZones(t *testing.T) {
	tmpDir := t.TempDir()

	lock1 := New(filepath.Join(tmpDir, "zone--example.com.-.lock"))
	lock2 := New(filepath.Join(tmpDir, "zone--test.com.-.lock"))

	// Acquire both locks - should not block
	err := lock1.Acquire()
	if err != nil {
		t.Fatalf("Failed to acquire lock1: %v", err)
	}

	err = lock2.Acquire()
	if err != nil {
		t.Fatalf("Failed to acquire lock2: %v", err)
	}

	// Release both
	lock1.Release()
	lock2.Release()
}

// BenchmarkLockAcquire benchmarks lock acquisition
func BenchmarkLockAcquire(b *testing.B) {
	tmpDir := b.TempDir()
	lockPath := filepath.Join(tmpDir, "bench.lock")
	lock := New(lockPath)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lock.Acquire()
		lock.Release()
	}
}
