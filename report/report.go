package report

import (
	"fmt"
	"time"

	"github.com/jung-kurt/gofpdf"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
)

type FileEraseLog struct {
	Path   string
	Status string
	Passes int
	Error  string
}

type HardwareInfo struct {
	Hostname string
	OS       string
	Platform string
	CPU      string
	MemTotal uint64
	MemUsed  uint64
}

type EraseReport struct {
	Dir          string
	StartTime    time.Time
	EndTime      time.Time
	Force        bool
	Stealth      bool
	Method       string
	Passes       int
	Logs         []FileEraseLog
	ErrorCount   int
	SuccessCount int
	Hardware     HardwareInfo
}

func NewEraseReport(dir string, passes int, force, stealth bool, method string) *EraseReport {
	hw := getHardwareInfo()
	return &EraseReport{
		Dir:       dir,
		Passes:    passes,
		Force:     force,
		Stealth:   stealth,
		Method:    method,
		StartTime: time.Now(),
		Hardware:  hw,
	}
}

func (r *EraseReport) AddLog(log FileEraseLog) {
	if log.Status == "WIPED" {
		r.SuccessCount++
	} else {
		r.ErrorCount++
	}
	r.Logs = append(r.Logs, log)
}

func (r *EraseReport) Complete() {
	r.EndTime = time.Now()
}

func (r *EraseReport) WritePDF(filename string) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 16)

	// Title
	pdf.CellFormat(0, 10, "Secure Erase Report", "", 1, "C", false, 0, "")

	// Report content
	pdf.SetFont("Arial", "", 12)
	status := "PASSED"
	if r.ErrorCount > 0 {
		status = "FAILED"
	}
	content := fmt.Sprintf("Directory: %s\nStart: %s\nEnd: %s\nPasses: %d\nForce: %v\nStealth: %v\nMethod: %s\nStatus: %s\n\n",
		r.Dir,
		r.StartTime.Format(time.RFC1123),
		r.EndTime.Format(time.RFC1123),
		r.Passes,
		r.Force,
		r.Stealth,
		r.Method,
		status,
	)
	pdf.MultiCell(0, 8, content, "", "L", false)

	// Hardware information
	hw := r.Hardware
	hardwareInfo := fmt.Sprintf("Hostname: %s\nOS: %s (%s)\nCPU: %s\nMemory: %.2f GB\n\n",
		hw.Hostname,
		hw.OS,
		hw.Platform,
		hw.CPU,
		float64(hw.MemTotal)/(1024*1024*1024),
	)
	pdf.MultiCell(0, 8, "Hardware Information:", "", "L", false)
	pdf.MultiCell(0, 8, hardwareInfo, "", "L", false)

	// Logs
	pdf.MultiCell(0, 8, "File Logs:", "", "L", false)
	for _, log := range r.Logs {
		row := fmt.Sprintf("- %s: %s (%d passes)", log.Path, log.Status, log.Passes)
		if log.Status != "WIPED" && log.Error != "" {
			row += fmt.Sprintf(" Error: %s", log.Error)
		}
		pdf.MultiCell(0, 6, row, "", "L", false)
	}

	return pdf.OutputFileAndClose(filename)
}

func getHardwareInfo() HardwareInfo {
	hw := HardwareInfo{}

	if info, err := host.Info(); err == nil {
		hw.Hostname = info.Hostname
		hw.OS = info.OS
		hw.Platform = info.Platform
	}

	if cpus, err := cpu.Info(); err == nil && len(cpus) > 0 {
		hw.CPU = fmt.Sprintf("%s %fMHz", cpus[0].ModelName, cpus[0].Mhz)
	}

	if vm, err := mem.VirtualMemory(); err == nil {
		hw.MemTotal = vm.Total
		hw.MemUsed = vm.Used
	}

	return hw
}
