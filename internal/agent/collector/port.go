package collector

import (
	"encoding/json"
	"gohids/internal/common"
	pb "gohids/pkg/protocol"
	"log"
	"time"

	"github.com/shirou/gopsutil/v3/net"
)

type PortCollector struct {
	stopCh chan struct{}
}

func NewPortCollector() *PortCollector {
	return &PortCollector{
		stopCh: make(chan struct{}),
	}
}

func (c *PortCollector) Name() string {
	return "Port"
}

func (c *PortCollector) Start(ch chan<- *pb.RawData) {
	// Report every 1 minute
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	// Initial report
	c.collectAndSend(ch)

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.collectAndSend(ch)
		}
	}
}

func (c *PortCollector) collectAndSend(ch chan<- *pb.RawData) {
	connections, err := net.Connections("all")
	if err != nil {
		log.Printf("Error getting connections: %v", err)
		return
	}

	var ports []map[string]interface{}

	for _, conn := range connections {
		if conn.Status == "LISTEN" {
			protocol := "TCP"
			if conn.Type == 2 { // UDP
				protocol = "UDP"
			}

			// Try to get process info (PID is in conn.Pid)
			// Process name resolution might be expensive, do it sparingly or use cache
			// For now, basic PID is good.

			portInfo := map[string]interface{}{
				"port":     conn.Laddr.Port,
				"protocol": protocol,
				"pid":      conn.Pid,
				"state":    conn.Status,
			}
			ports = append(ports, portInfo)
		}
	}

	if len(ports) > 0 {
		dataBytes, _ := json.Marshal(ports)
		data := createRawData(common.DataTypeAssetPort, map[string]string{
			"data": string(dataBytes),
		})
		data.Data[0].Timestamp = time.Now().Unix()
		ch <- data
	}
}

func (c *PortCollector) Stop() {
	close(c.stopCh)
}
