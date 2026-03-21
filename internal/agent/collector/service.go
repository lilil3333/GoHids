//go:build windows
// +build windows

package collector

import (
	"encoding/json"
	"fmt"
	"gohids/internal/common"
	pb "gohids/pkg/protocol"
	"log"
	"time"

	"golang.org/x/sys/windows/svc/mgr"
)

type ServiceCollector struct {
	stopCh chan struct{}
}

func NewServiceCollector() *ServiceCollector {
	return &ServiceCollector{
		stopCh: make(chan struct{}),
	}
}

func (c *ServiceCollector) Name() string {
	return "Service"
}

func (c *ServiceCollector) Start(ch chan<- *pb.RawData) {
	time.Sleep(5 * time.Second)
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			m, err := mgr.Connect()
			if err != nil {
				log.Printf("Failed to connect to service manager: %v", err)
				continue
			}

			services, err := m.ListServices()
			m.Disconnect()
			if err != nil {
				continue
			}

			// Only send count and first few for demo
			svcList := make([]map[string]interface{}, 0)
			for i, s := range services {
				if i >= 20 {
					break
				}
				svcList = append(svcList, map[string]interface{}{
					"name": s,
				})
			}

			dataBytes, _ := json.Marshal(svcList)
			data := createRawData(common.DataTypeService, map[string]string{
				"total_count": fmt.Sprintf("%d", len(services)),
				"data":        string(dataBytes),
			})
			data.Data[0].Timestamp = time.Now().Unix()
			ch <- data
			log.Printf("Sent service list (Total: %d)", len(services))
		}
	}
}

func (c *ServiceCollector) Stop() {
	close(c.stopCh)
}
