package collector

import (
	"encoding/json"
	"gohids/internal/common"
	pb "gohids/pkg/protocol"
	"log"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

type ProcessInfo struct {
	PID       int32
	PPID      int32
	Name      string
	Path      string // Added
	Cmdline   string
	Username  string
	StartTime int64
}

type ProcessCollector struct {
	stopCh chan struct{}
}

func NewProcessCollector() *ProcessCollector {
	return &ProcessCollector{
		stopCh: make(chan struct{}),
	}
}

func (c *ProcessCollector) Name() string {
	return "Process"
}

func (c *ProcessCollector) Start(ch chan<- *pb.RawData) {
	time.Sleep(2 * time.Second) // Wait a bit
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// Cache for Diff
	lastProcessMap := make(map[int32]ProcessInfo)

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			procs, err := process.Processes()
			if err != nil {
				continue
			}

			currentProcessMap := make(map[int32]ProcessInfo)
			var events []map[string]interface{}

			for _, p := range procs {
				pid := p.Pid
				name, err := p.Name()
				if err != nil && name == "" {
					name = "Unknown"
				}
				cmdline, _ := p.Cmdline()
				exe, _ := p.Exe() // Added
				ppid, _ := p.Ppid()
				username, _ := p.Username()
				createTime, _ := p.CreateTime()

				info := ProcessInfo{
					PID:       pid,
					PPID:      ppid,
					Name:      name,
					Path:      exe, // Added
					Cmdline:   cmdline,
					Username:  username,
					StartTime: createTime,
				}
				currentProcessMap[pid] = info

				// Check for NEW process (START)
				if _, exists := lastProcessMap[pid]; !exists {
					// Rule Check (Only on Start to avoid spam)
					if rule := GetRuleEngine().MatchProcess(info); rule != nil {
						log.Printf("[SECURITY ALERT] Process '%s' (PID: %d) matched rule: %s [SID:%s]", name, pid, rule.Msg, rule.SID)

						// Get Parent Info for Context
						var parentName string
						if parent, err := process.NewProcess(ppid); err == nil {
							parentName, _ = parent.Name()
						}

						// Construct Intrusion Alert Data
						alertData := map[string]interface{}{
							"rule_sid":     rule.SID,
							"rule_msg":     rule.Msg,
							"rule_class":   rule.ClassType,
							"process_pid":  pid,
							"process_name": name,
							"process_path": exe, // Added
							"process_cmd":  cmdline,
							"ppid":         ppid,
							"parent_name":  parentName,
							"timestamp":    time.Now().Unix(),
						}

						alertBytes, _ := json.Marshal(alertData)
						alertRaw := createRawData(common.DataTypeIntrusion, map[string]string{
							"data": string(alertBytes),
						})
						alertRaw.Data[0].Timestamp = time.Now().Unix()
						ch <- alertRaw
					}

					// START Event
					events = append(events, map[string]interface{}{
						"action":    "START",
						"pid":       pid,
						"ppid":      ppid,
						"name":      name,
						"path":      exe, // Added
						"cmdline":   cmdline,
						"user":      username,
						"timestamp": time.Now().Unix(),
					})
				}
			}

			// Check for EXIT process
			for pid, oldInfo := range lastProcessMap {
				if _, exists := currentProcessMap[pid]; !exists {
					// EXIT Event
					events = append(events, map[string]interface{}{
						"action":    "EXIT",
						"pid":       pid,
						"ppid":      oldInfo.PPID,
						"name":      oldInfo.Name,
						"path":      oldInfo.Path, // Added
						"cmdline":   oldInfo.Cmdline,
						"user":      oldInfo.Username,
						"timestamp": time.Now().Unix(),
					})
				}
			}

			// Update last state
			lastProcessMap = currentProcessMap

			// Send events if any
			if len(events) > 0 {
				log.Printf("Detected %d process events", len(events))
				dataBytes, _ := json.Marshal(events)
				data := createRawData(common.DataTypeProcess, map[string]string{
					"data": string(dataBytes),
				})
				data.Data[0].Timestamp = time.Now().Unix()
				ch <- data
			}
		}
	}
}

func (c *ProcessCollector) Stop() {
	close(c.stopCh)
}
