package detection

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/shirou/gopsutil/v3/disk"
	"golang.org/x/sys/windows/registry"
)

// Structure to store each user's data folders
type UserFolders struct {
	Desktop   string
	Documents string
	Downloads string
	Videos    string
	Music     string
	Pictures  string
}

func (uf UserFolders) All() []string {
	return []string{
		uf.Desktop,
		uf.Documents,
		uf.Downloads,
		uf.Videos,
		uf.Music,
		uf.Pictures,
	}
}

func GetAllUserDataFolders() ([]UserFolders, error) {
	var result []UserFolders
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, registry.READ)
	if err != nil {
		return nil, fmt.Errorf("cannot open ProfileList registry key: %v", err)
	}
	defer k.Close()
	sids, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("cannot enumerate user SIDs: %v", err)
	}
	for _, sid := range sids {
		subKey, err := registry.OpenKey(k, sid, registry.READ)
		if err != nil {
			continue
		}
		path, _, err := subKey.GetStringValue("ProfileImagePath")
		subKey.Close()
		if err != nil || !dirExists(path) || strings.Contains(path, "system32") {
			continue
		}
		uf := UserFolders{
			Desktop:   filepath.Join(path, "Desktop"),
			Documents: filepath.Join(path, "Documents"),
			Downloads: filepath.Join(path, "Downloads"),
			Videos:    filepath.Join(path, "Videos"),
			Music:     filepath.Join(path, "Music"),
			Pictures:  filepath.Join(path, "Pictures"),
		}
		result = append(result, uf)
	}
	return result, nil
}

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

// Helper to check directory existence
func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
