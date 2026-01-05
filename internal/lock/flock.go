package lock

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// Lock provides advisory file locking using flock semantics
type Lock struct {
	path     string
	file     *os.File
	held     bool
	mu       sync.Mutex
	readOnly bool
}

// New creates a new lock for the given path
func New(path string) *Lock {
	return &Lock{
		path:     path,
		readOnly: false,
	}
}

// NewReadOnly creates a new read-only (shared) lock
func NewReadOnly(path string) *Lock {
	return &Lock{
		path:     path,
		readOnly: true,
	}
}

// Acquire attempts to acquire the lock
// Returns an error if the lock cannot be acquired
func (l *Lock) Acquire() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.held {
		return fmt.Errorf("lock already held")
	}

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(l.path), 0755); err != nil {
		return fmt.Errorf("failed to create lock directory: %w", err)
	}

	// Open/create the lock file
	flags := os.O_CREATE | os.O_WRONLY
	if l.readOnly {
		flags = os.O_CREATE | os.O_RDONLY
	}

	f, err := os.OpenFile(l.path, flags, 0644)
	if err != nil {
		return fmt.Errorf("failed to open lock file: %w", err)
	}

	// Acquire the lock using flock
	how := syscall.LOCK_EX
	if l.readOnly {
		how = syscall.LOCK_SH
	}

	if err := syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB); err != nil {
		f.Close()
		return fmt.Errorf("failed to acquire lock: %w", err)
	}

	l.file = f
	l.held = true
	return nil
}

// Release releases the lock
func (l *Lock) Release() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.held {
		return nil
	}

	if err := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN); err != nil {
		return fmt.Errorf("failed to release lock: %w", err)
	}

	if err := l.file.Close(); err != nil {
		return fmt.Errorf("failed to close lock file: %w", err)
	}

	l.held = false
	l.file = nil
	return nil
}

// Held returns true if the lock is currently held
func (l *Lock) Held() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.held
}

// TryAcquire attempts to acquire the lock without blocking
// Returns true if successful, false if lock is held by another process
func (l *Lock) TryAcquire() bool {
	err := l.Acquire()
	return err == nil
}

// Close is an alias for Release for compatibility with defer patterns
func (l *Lock) Close() error {
	return l.Release()
}

// ZoneLockPath returns the lock file path for a zone
func ZoneLockPath(lockDir, zone string) string {
	// Remove trailing dot for filename
	zoneName := zone
	if len(zoneName) > 0 && zoneName[len(zoneName)-1] == '.' {
		zoneName = zoneName[:len(zoneName)-1]
	}
	return filepath.Join(lockDir, "zone--"+zoneName+".lock")
}

// CatalogLockPath returns the lock file path for the catalog zone
func CatalogLockPath(lockDir string) string {
	return filepath.Join(lockDir, "catalog.lock")
}
