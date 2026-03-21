package collector

import (
	"gohids/internal/common"
	pb "gohids/pkg/protocol"
	"log"
	"time"
)

type HeartbeatCollector struct {
	stopCh chan struct{}
}

func NewHeartbeatCollector() *HeartbeatCollector {
	return &HeartbeatCollector{
		stopCh: make(chan struct{}),
	}
}

func (c *HeartbeatCollector) Name() string {
	return "Heartbeat"
}

func (c *HeartbeatCollector) Start(ch chan<- *pb.RawData) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			data := createRawData(common.DataTypeHeartbeat, map[string]string{
				"status": "alive",
			})
			data.Data[0].Timestamp = time.Now().Unix()
			ch <- data
			log.Println("Sent heartbeat")
		}
	}
}

func (c *HeartbeatCollector) Stop() {
	close(c.stopCh)
}
