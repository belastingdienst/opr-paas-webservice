package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	timeout               = 10 * time.Millisecond
	waitForChange         = 2 * time.Second
	quietPeriod           = 100 * time.Millisecond
	fileModeUserReadWrite = 0o600
	dirMode               = 0o700
	concurrentCallers     = 20
	lastVersion           = 4 // three ConfigMap updates after the first mount
)

// requireTriggered waits until fw has seen a change: events arrive
// asynchronously, later under the race detector.
func requireTriggered(t *testing.T, fw *FileWatcher, msg string) {
	t.Helper()
	require.Eventually(t, fw.WasTriggered, waitForChange, timeout, msg)
}

func newWatcher(t *testing.T, paths ...string) *FileWatcher {
	t.Helper()
	fw := NewFileWatcher(paths...)
	t.Cleanup(func() { _ = fw.Close() })
	return fw
}

func writeFile(t *testing.T, path string, data string) {
	t.Logf("writing file %s", path)
	if err := os.WriteFile(path, []byte(data), fileModeUserReadWrite); err != nil {
		panic(fmt.Errorf("unable to write to file: %w", err))
	}
}

func Test_FolderChanged(t *testing.T) {
	// Create folder
	tmpDir, err := os.MkdirTemp("", "notifierFolderTest")
	if err != nil {
		panic(fmt.Errorf("unable to create temp dir: %w", err))
	}
	fw := newWatcher(t, tmpDir)
	time.Sleep(timeout)
	require.False(t, fw.WasTriggered(), "fileWatcher was not triggered after init")

	// create 3 files
	for _, filename := range []string{"f1", "f2", "f3"} {
		writeFile(t, filepath.Join(tmpDir, filename), filename)
	}

	requireTriggered(t, fw, "fileWatcher was triggered after creating 3 files")

	// add file
	writeFile(t, filepath.Join(tmpDir, "extra"), "extra file data")

	requireTriggered(t, fw, "fileWatcher was triggered after adding file")

	// change file
	writeFile(t, filepath.Join(tmpDir, "extra"), "other extra file data")
	requireTriggered(t, fw, "fileWatcher was triggered after adding file")
}

func Test_FileChanged(t *testing.T) {
	// Create folder
	tmpDir, err := os.MkdirTemp("", "notifierFileTest")
	if err != nil {
		panic(fmt.Errorf("unable to create temp dir: %w", err))
	}

	// add file
	filePath := filepath.Join(tmpDir, "extra")
	writeFile(t, filePath, "initial file data")
	fw := newWatcher(t, filePath)
	time.Sleep(timeout)
	require.False(t, fw.WasTriggered(), "fileWatcher was not triggered after init")

	writeFile(t, filePath, "other file data")
	requireTriggered(t, fw, "fileWatcher was triggered after writing to file")

	os.Remove(filePath)
	writeFile(t, filePath, "recreated file data")
	requireTriggered(t, fw, "fileWatcher was triggered after removing file")

	writeFile(t, filePath, "recreated file data again")
	requireTriggered(t, fw, "fileWatcher was triggered after recreating file")
}

func Test_LinkChanged(t *testing.T) {
	// Create folder
	tmpDir, err := os.MkdirTemp("", "notifierSymlinkTest")
	if err != nil {
		panic(fmt.Errorf("unable to create temp dir: %w", err))
	}

	// add file
	filePath := filepath.Join(tmpDir, "extra")
	writeFile(t, filePath, "initial file data")
	symlinkPath := filepath.Join(tmpDir, "symlink")
	if err = os.Symlink(filePath, symlinkPath); err != nil {
		panic(fmt.Errorf("unable to create symlink: %w", err))
	}

	fw := newWatcher(t, symlinkPath)
	time.Sleep(timeout)
	require.False(t, fw.WasTriggered(), "fileWatcher was not triggered after init")

	writeFile(t, filePath, "other symlink data")
	requireTriggered(t, fw, "fileWatcher was triggered after writing to symlink")

	// Replacing the symlink itself is seen through the parent directory by
	// inotify, but not always by kqueue; either way the target is watched again.
	os.Remove(symlinkPath)
	time.Sleep(timeout)
	if err = os.Symlink(filePath, symlinkPath); err != nil {
		panic(fmt.Errorf("unable to create symlink: %w", err))
	}
	time.Sleep(timeout)
	fw.WasTriggered()

	writeFile(t, filePath, "recreated symlink data")
	requireTriggered(t, fw, "fileWatcher was triggered after recreating symlink")
}

// mountConfigMap lays out dir the way the kubelet mounts a ConfigMap or Secret:
// the file is a symlink into `..data`, itself a symlink to a timestamped
// directory, and an update writes a new directory and swaps `..data`.
func mountConfigMap(t *testing.T, dir, name, data string, version int) {
	t.Helper()
	versioned := fmt.Sprintf("..2026_11_11_%02d", version)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, versioned), dirMode))
	writeFile(t, filepath.Join(dir, versioned, name), data)
	tmpLink := filepath.Join(dir, "..data_tmp")
	require.NoError(t, os.Symlink(versioned, tmpLink))
	require.NoError(t, os.Rename(tmpLink, filepath.Join(dir, "..data")))
	if version == 1 {
		require.NoError(t, os.Symlink(filepath.Join("..data", name), filepath.Join(dir, name)))
		return
	}
	require.NoError(t, os.RemoveAll(filepath.Join(dir, fmt.Sprintf("..2026_11_11_%02d", version-1))))
}

// The opr-paas deployment mounts only the public key: the private-key path is
// missing, and that must not stop the public key from being watched.
func Test_MissingPathDoesNotStopTheOthers(t *testing.T) {
	tmpDir := t.TempDir()
	privateKeys := filepath.Join(tmpDir, "privateKeys")
	publicDir := filepath.Join(tmpDir, "publickey")
	require.NoError(t, os.Mkdir(publicDir, dirMode))
	mountConfigMap(t, publicDir, "publicKey", "key 1", 1)

	fw := newWatcher(t, privateKeys, filepath.Join(publicDir, "publicKey"))
	time.Sleep(timeout)
	require.False(t, fw.WasTriggered(), "fileWatcher was not triggered after init")

	for version := 2; version <= lastVersion; version++ {
		mountConfigMap(t, publicDir, "publicKey", fmt.Sprintf("key %d", version), version)
		requireTriggered(t, fw, fmt.Sprintf("ConfigMap update %d was seen", version-1))
	}

	// The missing path is picked up once it appears, and then watched.
	require.NoError(t, os.Mkdir(privateKeys, dirMode))
	requireTriggered(t, fw, "the private-key directory appeared")
	writeFile(t, filepath.Join(privateKeys, "new"), "private key")
	requireTriggered(t, fw, "a key was added to the new private-key directory")
}

func Test_UnrelatedFilesNextToAPathAreIgnored(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "publicKey")
	writeFile(t, filePath, "key")
	fw := newWatcher(t, filePath)

	writeFile(t, filepath.Join(tmpDir, "unrelated"), "data")
	time.Sleep(quietPeriod)
	require.False(t, fw.WasTriggered(), "a file next to the watched path is not a change")
}

func Test_ConcurrentUse(t *testing.T) {
	tmpDir := t.TempDir()
	fw := newWatcher(t, tmpDir)
	var wg sync.WaitGroup
	for i := range concurrentCallers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			writeFile(t, filepath.Join(tmpDir, fmt.Sprintf("f%d", i)), "data")
			fw.WasTriggered()
			_ = fw.Generation()
		}()
	}
	wg.Wait()
	require.Eventually(t, func() bool { return fw.Generation() > 0 }, waitForChange, timeout)
}
