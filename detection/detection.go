package detection

import (
	"github.com/shirou/gopsutil/v3/disk"
	"os"
	"path/filepath"
)

func GetNonMountedPartitions() []string {
	// Get all partitions, including all physical and logical drives
	partitions, err := disk.Partitions(true)
	var nonSysPartitions []string
	if err != nil {
		//fmt.Printf("Error getting partitions: %v\n", err)
		return nonSysPartitions
	}
	var systemPartition string
	for _, p := range partitions {
		mountPoint := p.Mountpoint
		windowsPath := filepath.Join(mountPoint, "Windows")
		if dirExists(windowsPath) {
			systemPartition = p.Device
			//fmt.Printf("System partition detected: %s (mounted at %s)\n", p.Device, p.Mountpoint)
			break
		}
	}
	for _, p := range partitions {
		// Skip system partition
		if p.Device == systemPartition {
			continue
		}
		nonSysPartitions = append(nonSysPartitions, p.Device)
	}
	return nonSysPartitions
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}
