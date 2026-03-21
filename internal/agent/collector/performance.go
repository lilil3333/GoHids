package collector

import (
	"encoding/json"
	"fmt"
	"gohids/internal/common"
	pb "gohids/pkg/protocol"
	"log"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
)

type PerformanceCollector struct {
	stopCh chan struct{}
}

func NewPerformanceCollector() *PerformanceCollector {
	return &PerformanceCollector{
		stopCh: make(chan struct{}),
	}
}

func (c *PerformanceCollector) Name() string {
	return "Performance"
}

func (c *PerformanceCollector) Start(ch chan<- *pb.RawData) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			// CPU
			percent, err := cpu.Percent(0, false)
			cpuUsage := 0.0
			if err == nil && len(percent) > 0 {
				cpuUsage = percent[0]
			}

			// Memory
			v, err := mem.VirtualMemory()
			memUsage := 0.0
			if err == nil {
				memUsage = v.UsedPercent
			}

			// Disk
			parts, err := disk.Partitions(false)
			var diskInfo []map[string]interface{}
			if err == nil {
				for _, part := range parts {
					usage, err := disk.Usage(part.Mountpoint)
					if err == nil {
						diskInfo = append(diskInfo, map[string]interface{}{
							"path":  usage.Path,
							"total": usage.Total,
							"used":  usage.Used,
							"free":  usage.Free,
							"pcent": usage.UsedPercent,
						})
					}
				}
			}
			diskBytes, _ := json.Marshal(diskInfo)

			data := createRawData(common.DataTypePerformance, map[string]string{
				"cpu":    fmt.Sprintf("%.2f", cpuUsage),
				"memory": fmt.Sprintf("%.2f", memUsage),
				"disk":   string(diskBytes),
			})
			data.Data[0].Timestamp = time.Now().Unix()
			ch <- data
			log.Printf("Sent performance data (CPU: %.2f%%, Mem: %.2f%%)", cpuUsage, memUsage)
		}
	}
}

func (c *PerformanceCollector) Stop() {
	close(c.stopCh)
}
