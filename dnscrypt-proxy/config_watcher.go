package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/jedisct1/dlog"
)

// ConfigWatcher monitors configuration files for changes and safely reloads them
type ConfigWatcher struct {
	watchedFiles map[string]*WatchedFile
	mu           sync.RWMutex
	watcher      *fsnotify.Watcher
	shutdownCh   chan struct{}
	// Debounce timers per file to avoid redundant checks
	debounceTimers map[string]*time.Timer
	debounceMu     sync.Mutex
}

// WatchedFile stores information about a file being monitored for changes
type WatchedFile struct {
	path       string
	lastHash   []byte
	lastSize   int64
	lastMod    time.Time
	reloadFunc func() error
	mu         sync.Mutex
	hashBuf    *bytes.Buffer // Reuse buffer for hashing
}

const (
	// Reduced debounce time for faster detection
	debounceInterval = 50 * time.Millisecond
	// Stability check interval - reduced from 100ms
	stabilityCheckInterval = 50 * time.Millisecond
	// Buffer size for io.Copy operations
	bufferSize = 32 * 1024
)

// NewConfigWatcher creates a new configuration file watcher
func NewConfigWatcher(interval time.Duration) *ConfigWatcher {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		dlog.Errorf("Failed to create file system watcher: %v", err)
		dlog.Notice("Falling back to polling-based file monitoring")
		return newPollingConfigWatcher(interval)
	}

	cw := &ConfigWatcher{
		watchedFiles:   make(map[string]*WatchedFile),
		watcher:        watcher,
		shutdownCh:     make(chan struct{}),
		debounceTimers: make(map[string]*time.Timer),
	}

	go cw.watchLoop()
	return cw
}

// watchLoop processes file system events
func (cw *ConfigWatcher) watchLoop() {
	for {
		select {
		case event, ok := <-cw.watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				cw.handleModifyEvent(event.Name)
			}
		case err, ok := <-cw.watcher.Errors:
			if !ok {
				return
			}
			dlog.Errorf("File watcher error: %v", err)
		case <-cw.shutdownCh:
			cw.watcher.Close()
			return
		}
	}
}

// handleModifyEvent handles a file modification event with debouncing
func (cw *ConfigWatcher) handleModifyEvent(path string) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		dlog.Debugf("Could not get absolute path for %s: %v", path, err)
		return
	}

	// Fast path: check if file exists in watched files before locking
	cw.mu.RLock()
	wf, exists := cw.watchedFiles[absPath]
	cw.mu.RUnlock()

	if !exists {
		return
	}

	// Debounce rapid changes - reset timer if exists
	cw.debounceMu.Lock()
	if oldTimer, exists := cw.debounceTimers[absPath]; exists {
		oldTimer.Stop()
	}

	timer := time.AfterFunc(debounceInterval, func() {
		cw.checkFileForChanges(wf)
		cw.debounceMu.Lock()
		delete(cw.debounceTimers, absPath)
		cw.debounceMu.Unlock()
	})

	cw.debounceTimers[absPath] = timer
	cw.debounceMu.Unlock()
}

// checkFileForChanges checks if a specific file has changed and is stable
// Optimized: single hash computation instead of double
func (cw *ConfigWatcher) checkFileForChanges(wf *WatchedFile) {
	wf.mu.Lock()
	defer wf.mu.Unlock()

	// Get file information - quick stat
	fileInfo, err := os.Stat(wf.path)
	if err != nil {
		dlog.Debugf("Cannot stat file [%s]: %v", wf.path, err)
		return
	}

	size1 := fileInfo.Size()

	// Fast path: if size matches last known size, likely no change
	// This avoids hashing entirely in many cases
	if size1 == wf.lastSize {
		return
	}

	// Get hash with buffered reading
	hash1, err := getFileHashBuffered(wf.path)
	if err != nil {
		dlog.Debugf("Cannot read file [%s]: %v", wf.path, err)
		return
	}

	// Wait a moment to see if the file is still changing
	time.Sleep(stabilityCheckInterval)

	fileInfo, err = os.Stat(wf.path)
	if err != nil {
		return
	}

	size2 := fileInfo.Size()

	// If size changed, file is still being written
	if size1 != size2 {
		dlog.Debugf("File [%s] is still being modified (size changed), waiting for stability", wf.path)
		return
	}

	// Only hash again if size is now stable
	hash2, err := getFileHashBuffered(wf.path)
	if err != nil {
		return
	}

	// If hash is different, file is still changing
	if !bytes.Equal(hash1, hash2) {
		dlog.Debugf("File [%s] is still being modified (hash changed), waiting for stability", wf.path)
		return
	}

	// The file appears stable, check if it's different from last loaded version
	if wf.lastSize == size2 && bytes.Equal(wf.lastHash, hash2) {
		// Content hasn't changed despite mod time change
		wf.lastMod = fileInfo.ModTime()
		return
	}

	// File has changed and is stable, reload it
	dlog.Noticef("Configuration file [%s] has changed, reloading", wf.path)
	if err := wf.reloadFunc(); err != nil {
		dlog.Errorf("Failed to reload [%s]: %v", wf.path, err)
		return
	}

	// Update file info after successful reload
	wf.lastHash = hash2
	wf.lastSize = size2
	wf.lastMod = fileInfo.ModTime()
	dlog.Noticef("Successfully reloaded [%s]", wf.path)
}

// AddFile registers a file to be watched for changes
func (cw *ConfigWatcher) AddFile(path string, reloadFunc func() error) error {
	if path == "" {
		return errors.New("empty file path")
	}
	if reloadFunc == nil {
		return errors.New("reload function is nil")
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	// Check if file exists and is readable
	fileInfo, err := os.Stat(absPath)
	if err != nil {
		return err
	}
	if fileInfo.IsDir() {
		return errors.New("path is a directory, not a file")
	}

	// Calculate initial hash
	hash, err := getFileHashBuffered(absPath)
	if err != nil {
		return err
	}

	wf := &WatchedFile{
		path:       absPath,
		lastHash:   hash,
		lastSize:   fileInfo.Size(),
		lastMod:    fileInfo.ModTime(),
		reloadFunc: reloadFunc,
		hashBuf:    bytes.NewBuffer(make([]byte, 0, bufferSize)),
	}

	cw.mu.Lock()
	defer cw.mu.Unlock()

	// Add to tracked files
	cw.watchedFiles[absPath] = wf

	// Watch directory containing the file to catch moves/renames when fsnotify is available
	if cw.watcher != nil {
		dirPath := filepath.Dir(absPath)
		if err := cw.watcher.Add(dirPath); err != nil {
			return err
		}
	}

	dlog.Noticef("Now watching [%s] for changes", absPath)
	return nil
}

// RemoveFile stops watching a file
func (cw *ConfigWatcher) RemoveFile(path string) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return
	}

	cw.mu.Lock()
	defer cw.mu.Unlock()

	if _, exists := cw.watchedFiles[absPath]; exists {
		delete(cw.watchedFiles, absPath)
		dlog.Noticef("Stopped watching [%s]", absPath)
	}

	// Clean up any pending debounce timers
	cw.debounceMu.Lock()
	if timer, exists := cw.debounceTimers[absPath]; exists {
		timer.Stop()
		delete(cw.debounceTimers, absPath)
	}
	cw.debounceMu.Unlock()
}

// Shutdown stops the watcher
func (cw *ConfigWatcher) Shutdown() {
	// Cancel all pending debounce timers
	cw.debounceMu.Lock()
	for _, timer := range cw.debounceTimers {
		timer.Stop()
	}
	cw.debounceTimers = make(map[string]*time.Timer)
	cw.debounceMu.Unlock()

	close(cw.shutdownCh)
}

// newPollingConfigWatcher creates a fallback polling-based watcher if fsnotify fails
func newPollingConfigWatcher(interval time.Duration) *ConfigWatcher {
	if interval <= 0 {
		interval = 1 * time.Second
	}

	cw := &ConfigWatcher{
		watchedFiles:   make(map[string]*WatchedFile),
		debounceTimers: make(map[string]*time.Timer),
		shutdownCh:     make(chan struct{}),
	}

	// Start a goroutine for polling
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				cw.checkAllFiles()
			case <-cw.shutdownCh:
				return
			}
		}
	}()

	return cw
}

// checkAllFiles examines all watched files for changes (used in polling mode)
func (cw *ConfigWatcher) checkAllFiles() {
	cw.mu.RLock()
	// Preallocate with exact size for better performance
	files := make([]*WatchedFile, 0, len(cw.watchedFiles))
	for _, wf := range cw.watchedFiles {
		files = append(files, wf)
	}
	cw.mu.RUnlock()

	for _, wf := range files {
		cw.checkFileForChanges(wf)
	}
}

// getFileHashBuffered calculates SHA-256 hash with buffered I/O for better performance
func getFileHashBuffered(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	hash := sha256.New()
	// Use buffered reader with larger buffer for reduced syscalls
	if _, err := io.CopyBuffer(hash, file, make([]byte, bufferSize)); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}
