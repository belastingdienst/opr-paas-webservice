package utils

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/fsnotify/fsnotify"
)

// FileWatcher counts changes to a set of files and directories.
//
// Each path is watched through its parent directory as well as by itself, so
// a path that does not exist yet is picked up when it appears, and a
// Kubernetes Secret or ConfigMap update, which swaps the `..data` symlink next
// to the mounted files, is seen too. A path that cannot be watched is logged
// once and does not stop the other paths from being watched.
type FileWatcher struct {
	watcher    *fsnotify.Watcher
	paths      []string
	generation atomic.Uint64
	seen       atomic.Uint64

	mu     sync.Mutex
	failed map[string]bool // paths whose watch failed, so each is logged once
}

// NewFileWatcher starts watching paths (empty paths are skipped) and returns
// the FileWatcher; changes are counted in a separate goroutine.
func NewFileWatcher(paths ...string) *FileWatcher {
	fw := &FileWatcher{failed: make(map[string]bool)}
	for _, p := range paths {
		if p != "" {
			fw.paths = append(fw.paths, filepath.Clean(p))
		}
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("ERROR: cannot watch %v for changes; changed keys are only read after a restart: %v",
			fw.paths, err)
		return fw
	}
	fw.watcher = watcher
	fw.Refresh()
	go fw.watchLoop()
	return fw
}

// Generation is the number of changes seen so far. It only grows, and is safe
// for concurrent use.
func (fw *FileWatcher) Generation() uint64 {
	return fw.generation.Load()
}

// WasTriggered reports whether a change was seen since the previous call.
func (fw *FileWatcher) WasTriggered() bool {
	current := fw.generation.Load()
	return fw.seen.Swap(current) != current
}

// Close stops watching.
func (fw *FileWatcher) Close() error {
	if fw.watcher == nil {
		return nil
	}
	return fw.watcher.Close()
}

// Refresh (re-)adds the watches. A watch ends when its path is removed or
// renamed, which is how Kubernetes updates a mounted Secret or ConfigMap, so
// this runs again after every change. Adding a path that is already watched
// does nothing.
func (fw *FileWatcher) Refresh() {
	if fw.watcher == nil {
		return
	}
	for _, p := range fw.paths {
		fw.add(filepath.Dir(p), true)
		fw.add(p, false)
	}
}

// add watches path. A path that does not exist is only an error for a parent
// directory: the watched path itself may appear later.
func (fw *FileWatcher) add(path string, mustExist bool) {
	if _, err := os.Stat(path); err != nil && !mustExist {
		return
	}
	err := fw.watcher.Add(path)
	fw.mu.Lock()
	defer fw.mu.Unlock()
	if err == nil {
		delete(fw.failed, path)
		return
	}
	if !fw.failed[path] {
		fw.failed[path] = true
		log.Printf("ERROR: cannot watch %q for changes: %v", path, err)
	}
}

// relevant reports whether an event on name is a change of a watched path:
// the path itself, a file inside it (a directory of keys), or a `..`-prefixed
// entry next to it (the `..data` symlink Kubernetes swaps on an update).
func (fw *FileWatcher) relevant(name string) bool {
	name = filepath.Clean(name)
	dir, base := filepath.Dir(name), filepath.Base(name)
	for _, p := range fw.paths {
		if name == p || dir == p || (dir == filepath.Dir(p) && strings.HasPrefix(base, "..")) {
			return true
		}
	}
	return false
}

// watchLoop counts the relevant events until the watcher is closed.
func (fw *FileWatcher) watchLoop() {
	for {
		select {
		case err, ok := <-fw.watcher.Errors:
			if !ok { // Channel was closed (i.e. Watcher.Close() was called).
				return
			}
			log.Printf("ERROR: watching key files: %s", err)
		case e, ok := <-fw.watcher.Events:
			if !ok { // Channel was closed (i.e. Watcher.Close() was called).
				return
			}
			if !fw.relevant(e.Name) {
				continue
			}
			generation := fw.generation.Add(1)
			log.Printf("key file change %d: %s", generation, e)
			fw.Refresh()
		}
	}
}
