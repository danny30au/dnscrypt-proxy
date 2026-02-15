package main

import (
	"io"
	"os"

	"github.com/jedisct1/dlog"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Logger returns an io.Writer that handles log rotation or direct output to special files/stdout.
func Logger(logMaxSize, logMaxAge, logMaxBackups int, fileName string) io.Writer {
	// Handle stdout directly.
	if fileName == "/dev/stdout" {
		return os.Stdout
	}

	// Check if the file exists and its type.
	info, err := os.Stat(fileName)
	if err == nil && !info.Mode().IsRegular() {
		if info.IsDir() {
			dlog.Fatalf("[%s] is a directory", fileName)
		}

		// Special files (devices, pipes) are opened directly without rotation.
		fp, err := os.OpenFile(fileName, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
		if err != nil {
			dlog.Fatalf("Unable to access special file [%s]: %v", fileName, err)
		}
		return fp
	}

	// Verify we have permission to create/write the file before setting up the rotated logger.
	if fp, err := os.OpenFile(fileName, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644); err == nil {
		fp.Close()
	} else {
		dlog.Errorf("Unable to create/access log file [%s]: %v", fileName, err)
	}

	// Return a lumberjack logger for standard files with rotation enabled.
	return &lumberjack.Logger{
		LocalTime:  true,
		MaxSize:    logMaxSize,
		MaxAge:     logMaxAge,
		MaxBackups: logMaxBackups,
		Filename:   fileName,
		Compress:   true,
	}
}
