package collector

import (
	"encoding/json"
	"fmt"
	"gohids/internal/common"
	pb "gohids/pkg/protocol"
	"log"
	"time"

	gnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

type NetworkInfo struct {
	PID         int32
	ProcessName string
	ProcessPath string // Added
	Cmdline     string // Added
	Family      uint32
	Type        uint32
	Laddr       gnet.Addr
	Raddr       gnet.Addr
	Status      string
}

type NetworkCollector struct {
	stopCh chan struct{}
}

func NewNetworkCollector() *NetworkCollector {
	return &NetworkCollector{
		stopCh: make(chan struct{}),
	}
}

func (c *NetworkCollector) Name() string {
	return "Network"
}

func (c *NetworkCollector) Start(ch chan<- *pb.RawData) {
	time.Sleep(3 * time.Second)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// Key: "Protocol|SrcIP:Port|DstIP:Port"
	lastNetMap := make(map[string]NetworkInfo)

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			conns, err := gnet.Connections("inet")
			if err != nil {
				continue
			}

			currentNetMap := make(map[string]NetworkInfo)
			var events []map[string]interface{}

			for _, c := range conns {
				// Filter local loopback addresses
				// raddr.IP might be empty if not connected
				rIP := c.Raddr.IP
				if rIP == "" || rIP == "127.0.0.1" || rIP == "::1" || rIP == "0.0.0.0" || rIP == "::" || rIP == "::0" {
					continue
				}

				// Enrich with Process Info
				var procName, procPath, procCmd string
				if c.Pid > 0 {
					if p, err := process.NewProcess(c.Pid); err == nil {
						procName, _ = p.Name()
						procPath, _ = p.Exe()
						cmdSlice, _ := p.CmdlineSlice()
						if len(cmdSlice) > 0 {
							procCmd = fmt.Sprintf("%v", cmdSlice)
						}
					}
				}

				// Generate Key
				protocol := "TCP"
				if c.Type == 2 { // SOCK_DGRAM
					protocol = "UDP"
				}
				key := fmt.Sprintf("%s|%s:%d|%s:%d", protocol, c.Laddr.IP, c.Laddr.Port, c.Raddr.IP, c.Raddr.Port)

				info := NetworkInfo{
					PID:         c.Pid,
					ProcessName: procName,
					ProcessPath: procPath,
					Cmdline:     procCmd,
					Family:      c.Family,
					Type:        c.Type,
					Laddr:       c.Laddr,
					Raddr:       c.Raddr,
					Status:      c.Status,
				}
				currentNetMap[key] = info

				// Check for NEW connection (CONNECT)
				if _, exists := lastNetMap[key]; !exists {
					events = append(events, map[string]interface{}{
						"action":       "CONNECT",
						"pid":          c.Pid,
						"process_name": procName,
						"process_path": procPath,
						"cmdline":      procCmd,
						"protocol":     protocol,
						"src_ip":       c.Laddr.IP,
						"src_port":     c.Laddr.Port,
						"dst_ip":       c.Raddr.IP,
						"dst_port":     c.Raddr.Port,
						"status":       c.Status,
						"timestamp":    time.Now().Unix(),
					})
				}
			}

			// Check for DISCONNECT
			for key, oldInfo := range lastNetMap {
				if _, exists := currentNetMap[key]; !exists {
					protocol := "TCP"
					if oldInfo.Type == 2 {
						protocol = "UDP"
					}
					events = append(events, map[string]interface{}{
						"action":       "DISCONNECT",
						"pid":          oldInfo.PID,
						"process_name": oldInfo.ProcessName,
						"process_path": oldInfo.ProcessPath,
						"cmdline":      oldInfo.Cmdline,
						"protocol":     protocol,
						"src_ip":       oldInfo.Laddr.IP,
						"src_port":     oldInfo.Laddr.Port,
						"dst_ip":       oldInfo.Raddr.IP,
						"dst_port":     oldInfo.Raddr.Port,
						"status":       oldInfo.Status,
						"timestamp":    time.Now().Unix(),
					})
				}
			}

			lastNetMap = currentNetMap

			if len(events) > 0 {
				log.Printf("Detected %d network events", len(events))
				dataBytes, _ := json.Marshal(events)
				data := createRawData(common.DataTypeNetwork, map[string]string{
					"data": string(dataBytes),
				})
				data.Data[0].Timestamp = time.Now().Unix()
				ch <- data
			}
		}
	}
}

func (c *NetworkCollector) Stop() {
	close(c.stopCh)
}
