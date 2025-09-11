package report

import (
	"fmt"
	"os"
	"time"
)

type FileEraseLog struct {
	Path   string
	Status string // "WIPED", "FAILED"
	Passes int
	Error  string
}

type EraseReport struct {
	Dir          string
	StartTime    time.Time
	EndTime      time.Time
	Force        bool
	Stealth      bool
	Passes       int
	Logs         []FileEraseLog
	ErrorCount   int
	SuccessCount int
}

func NewEraseReport(dir string, passes int, force, stealth bool) *EraseReport {
	return &EraseReport{
		Dir:       dir,
		Passes:    passes,
		Force:     force,
		Stealth:   stealth,
		StartTime: time.Now(),
	}
}

func (r *EraseReport) AddLog(log FileEraseLog) {
	if log.Status == "WIPED" {
		r.SuccessCount++
	} else if log.Status == "FAILED" {
		r.ErrorCount++
	}
	r.Logs = append(r.Logs, log)
}

func (r *EraseReport) Complete() {
	r.EndTime = time.Now()
}

func (r *EraseReport) WriteToFile(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	fmt.Fprintf(f, "===================================\n Secure Erase Report\n===================================\n\n")
	fmt.Fprintf(f, "Target directory : %s\nErase date/time  : %v\nWipe passes      : %d\nForce mode       : %v\nStealth mode     : %v\nOperation status : %s\n\nFiles erased:\n",
		r.Dir, r.StartTime.Format(time.RFC1123), r.Passes, r.Force, r.Stealth,
		ifThenElse(r.ErrorCount == 0, "PASSED", "FAILED"),
	)
	for _, log := range r.Logs {
		if log.Status == "WIPED" {
			fmt.Fprintf(f, "- %s : [WIPED] (%d passes)\n", log.Path, log.Passes)
		} else {
			fmt.Fprintf(f, "- %s : [FAILED] (%d passes) Reason: %s\n", log.Path, log.Passes, log.Error)
		}
	}
	fmt.Fprintf(f, "\nTotal files successfully erased: %d\nTotal files failed: %d\nElapsed time: %v\n",
		r.SuccessCount, r.ErrorCount, r.EndTime.Sub(r.StartTime))
	return nil
}

func ifThenElse(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}
