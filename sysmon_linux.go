//go:build linux

package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type CPUTicks struct {
	Idle  uint64
	Total uint64
}

func getCPUTicks() (CPUTicks, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return CPUTicks{}, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "cpu" {
			return CPUTicks{}, fmt.Errorf("invalid stat file format")
		}

		var total uint64
		var idle uint64
		for i := 1; i < len(fields); i++ {
			val, err := strconv.ParseUint(fields[i], 10, 64)
			if err != nil {
				continue
			}
			total += val
			if i == 4 || i == 5 { // idle and iowait are idle ticks
				idle += val
			}
		}
		return CPUTicks{Idle: idle, Total: total}, nil
	}
	return CPUTicks{}, fmt.Errorf("empty stat file")
}

func getCPUUsage() (float64, error) {
	t1, err := getCPUTicks()
	if err != nil {
		return 0, err
	}
	time.Sleep(500 * time.Millisecond)
	t2, err := getCPUTicks()
	if err != nil {
		return 0, err
	}

	idleDelta := t2.Idle - t1.Idle
	totalDelta := t2.Total - t1.Total
	if totalDelta == 0 {
		return 0, nil
	}
	return (1.0 - float64(idleDelta)/float64(totalDelta)) * 100, nil
}

func getMemoryUsage() (total, available uint64, err error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	var free, buffers, cached uint64
	hasAvailable := false

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, _ := strconv.ParseUint(fields[1], 10, 64) // in kB
		switch fields[0] {
		case "MemTotal:":
			total = val * 1024
		case "MemAvailable:":
			available = val * 1024
			hasAvailable = true
		case "MemFree:":
			free = val * 1024
		case "Buffers:":
			buffers = val * 1024
		case "Cached:":
			cached = val * 1024
		}
	}

	if !hasAvailable {
		available = free + buffers + cached
	}
	return total, available, nil
}

func getDiskUsage(path string) (total, free uint64, err error) {
	var stat syscall.Statfs_t
	err = syscall.Statfs(path, &stat)
	if err != nil {
		return 0, 0, err
	}
	total = stat.Blocks * uint64(stat.Bsize)
	free = stat.Bfree * uint64(stat.Bsize)
	return total, free, nil
}
