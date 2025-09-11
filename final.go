package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
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

// secureDeleteDir overwrites all files multiple times, tries to take ownership and set permissions if force,
// then deletes the directory entirely.
func secureDeleteDir(dir string, passes int, force bool, silent bool) error {
	err := filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
		// Handle errors reading file/directory metadata gracefully:
		if walkErr != nil {
			if !silent {
				fmt.Printf("Skipping path %q due to error: %v\n", path, walkErr)
			}
			return nil // Continue walking without treating as fatal
		}
		if !info.IsDir() {
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
			for i := range passes {
				if err := overwriteFile(path); err != nil {

					if !silent {
						fmt.Printf("Failed to overwrite file %s on pass %d: %v\n", path, i+1, err)

					}
					break // skip further attempts on this file
				}
			}
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

type WipeConfig struct {
	passes  int
	stealth bool
	force   bool
}

func main() {
	config := WipeConfig{
		passes:  5,
		stealth: true,
		force:   true,
	}
	silent := config.stealth
	force := config.force
	passes := config.passes
	dir := "C:/Users/Admin/Downloads"

	fi, err := os.Stat(dir)
	if err != nil {
		if !silent {
			log.Fatalf("Failed to stat directory: %v", err)
		}
	}
	if !fi.IsDir() {
		if !silent {
			log.Fatalf("%s is not a directory", dir)
		}
	}

	if !silent {
		fmt.Printf("Starting secure wipe of directory: %s with %d passes, force: %v\n", dir, passes, force)
	}
	if err := secureDeleteDir(dir, passes, force, silent); err != nil {
		if !silent {
			log.Fatalf("Secure wipe failed: %v", err)
		}
	}
}
