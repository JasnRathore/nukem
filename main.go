package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"
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
			return fmt.Errorf("short random read: %d bytes", n)
		}

		toWrite := bufSize
		if remaining := size - totalWritten; int64(toWrite) > remaining {
			toWrite = int(remaining)
		}

		wn, err := file.Write(buf[:toWrite])
		if err != nil {
			return fmt.Errorf("failed to write to file %s: %v", path, err)
		}
		if wn != toWrite {
			return fmt.Errorf("short write to file %s: wrote %d bytes instead of %d", path, wn, toWrite)
		}

		totalWritten += int64(wn)
	}

	err = file.Sync()
	if err != nil {
		return fmt.Errorf("failed to sync file %s: %v", path, err)
	}

	return nil
}

func secureDeleteDir(dir string) error {
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			fmt.Printf("Overwriting file: %s\n", path)
			if err := overwriteFile(path); err != nil {
				return err
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

	fmt.Printf("Securely deleted directory: %s\n", dir)
	return nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: go run main.go <directory_path>")
		os.Exit(1)
	}

	dir := os.Args[1]

	fi, err := os.Stat(dir)
	if err != nil {
		log.Fatalf("Failed to stat directory: %v", err)
	}
	if !fi.IsDir() {
		log.Fatalf("%s is not a directory", dir)
	}

	fmt.Printf("Starting secure deletion of directory: %s\n", dir)
	err = secureDeleteDir(dir)
	if err != nil {
		log.Fatalf("Secure deletion failed: %v", err)
	}
}
