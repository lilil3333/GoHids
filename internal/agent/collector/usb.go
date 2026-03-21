//go:build windows
// +build windows

package collector

import (
	"gohids/internal/common"
	pb "gohids/pkg/protocol"
	"log"
	"time"

	"github.com/shirou/gopsutil/v3/disk"
)

type USBCollector struct {
	stopCh chan struct{}
}

func NewUSBCollector() *USBCollector {
	return &USBCollector{
		stopCh: make(chan struct{}),
	}
}

func (c *USBCollector) Name() string {
	return "USB"
}

func (c *USBCollector) Start(ch chan<- *pb.RawData) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	lastDrives := make(map[string]bool)

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			parts, err := disk.Partitions(false)
			if err != nil {
				continue
			}

			currentDrives := make(map[string]bool)
			for _, part := range parts {
				currentDrives[part.Mountpoint] = true

				if !lastDrives[part.Mountpoint] && len(lastDrives) > 0 {
					log.Printf("New drive detected: %s (%s)", part.Mountpoint, part.Fstype)
					data := createRawData(common.DataTypeUSB, map[string]string{
						"event":      "INSERT",
						"mountpoint": part.Mountpoint,
						"fstype":     part.Fstype,
					})
					data.Data[0].Timestamp = time.Now().Unix()
					ch <- data
				}
			}

			for mount := range lastDrives {
				if !currentDrives[mount] {
					log.Printf("Drive removed: %s", mount)
					data := createRawData(common.DataTypeUSB, map[string]string{
						"event":      "REMOVE",
						"mountpoint": mount,
					})
					data.Data[0].Timestamp = time.Now().Unix()
					ch <- data
				}
			}
			lastDrives = currentDrives
		}
	}
}

func (c *USBCollector) Stop() {
	close(c.stopCh)
}
