//go:build windows

package main

import (
	"time"
)

func getCPUUsage() (float64, error) {
	// Giả lập CPU usage
	time.Sleep(500 * time.Millisecond)
	return 15.4, nil
}

func getMemoryUsage() (total, available uint64, err error) {
	// Giả lập RAM: 8GB total, 4.2GB available
	total = 8 * 1024 * 1024 * 1024
	available = 4200 * 1024 * 1024
	return total, available, nil
}

func getDiskUsage(path string) (total, free uint64, err error) {
	// Giả lập Disk: 100GB total, 62GB free
	total = 100 * 1024 * 1024 * 1024
	free = 62 * 1024 * 1024 * 1024
	return total, free, nil
}
