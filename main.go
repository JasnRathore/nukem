package main

import (
	"crypto/rand"
	"fmt"
	"github.com/google/uuid"
	"log"
	"nukem/report"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

func overwriteFile(path string) error {
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

	bufSize := 4096
	buf := make([]byte, bufSize)

	var totalWritten int64
	for totalWritten < size {
		n, err := rand.Read(buf)
		if err != nil {
			return fmt.Errorf("failed to read random data: %v", err)
		}
		if n != bufSize {
			return fmt.Errorf("short random read: %d", n)
		}
		toWrite := bufSize
		if remaining := size - totalWritten; int64(toWrite) > remaining {
			toWrite = int(remaining)
		}
		wn, err := file.Write(buf[:toWrite])
		if err != nil {
			return fmt.Errorf("failed writing to file %s: %v", path, err)
		}
		if wn != toWrite {
			return fmt.Errorf("short write to file %s: wrote %d bytes instead of %d", path, wn, toWrite)
		}
		totalWritten += int64(wn)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync file %s: %v", path, err)
	}
	return nil
}

func takeOwnership(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}

	var cmd *exec.Cmd
	if fi.IsDir() {
		// Use /R (recursive) on directories
		cmd = exec.Command("takeown", "/F", path, "/R", "/D", "Y")
	} else {
		// No /R for files
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
	mode := fi.Mode() | 0200 // add user write permission
	return os.Chmod(path, mode)
}

// grantFullControl grants full control permissions recursively using 'icacls'.
func grantFullControl(path string) error {
	cmd := exec.Command("icacls", path, "/grant", "Administrators:F", "/T", "/C")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls failed: %v, output: %s", err, string(out))
	}
	return nil
}

func secureDeleteDir(dir string, passes int, force bool, silent bool, rep *report.EraseReport) error {
	err := filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			rep.AddLog(report.FileEraseLog{Path: path, Status: "FAILED", Passes: passes, Error: walkErr.Error()})
			return nil
		}
		if !info.IsDir() {
			status := "WIPED"
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
			var errText string
			if !silent {
				fmt.Printf("Overwriting file: %s\n", path)
			}
			for i := 0; i < passes; i++ {
				if err := overwriteFile(path); err != nil {
					status = "FAILED"
					errText = err.Error()
					break
				}
			}

			if status != "FAILED" {
				err := os.Remove(path)
				if err != nil {
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
		return nil
	})
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

func secureDeleteDirConcurrent(dir string, passes int, force bool, silent bool, rep *report.EraseReport, workerCount int) error {
	files := make(chan string, workerCount)
	var wg sync.WaitGroup

	// Worker function to overwrite files
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

			for i := 0; i < passes; i++ {
				if err := overwriteFile(path); err != nil {
					status = "FAILED"
					errText = err.Error()
					break
				}
			}
			if status != "FAILED" {
				err := os.Remove(path)
				if err != nil {
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

	// Start worker goroutines
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go worker()
	}

	// Walk directory and send file paths to workers
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

	// Remove directory after files are deleted
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
	dir := "C:/Users/Jasn/danger"
	passes := 3
	force := true
	stealth := true
	rep := report.NewEraseReport(dir, passes, force, stealth)

	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		log.Fatal("Invalid directory")
	}

	if err := secureDeleteDirConcurrent(dir, passes, force, stealth, rep, 20); err != nil {
		log.Printf("Error during wipe: %v\n", err)
	}
	rep.Complete()
	uid := uuid.New().String()

	pdfName := fmt.Sprintf("reports/erasure_report_%s.pdf", uid)
	if err := rep.WritePDF(pdfName); err != nil {
		log.Fatalf("Failed to create PDF: %v", err)
	}
	log.Println("Erase report generated.")
}
