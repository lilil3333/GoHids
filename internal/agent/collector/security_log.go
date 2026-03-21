//go:build windows
// +build windows

package collector

import (
	"encoding/json"
	"fmt"
	"gohids/internal/common"
	pb "gohids/pkg/protocol"
	"log"
	"os/exec"
	"time"
)

type SecurityLogCollector struct {
	stopCh chan struct{}
}

func NewSecurityLogCollector() *SecurityLogCollector {
	return &SecurityLogCollector{
		stopCh: make(chan struct{}),
	}
}

func (c *SecurityLogCollector) Name() string {
	return "SecurityLog"
}

func (c *SecurityLogCollector) Start(ch chan<- *pb.RawData) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	lastTime := time.Now().Add(-1 * time.Minute)

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			psScript := fmt.Sprintf(`
			$events = Get-WinEvent -FilterHashTable @{LogName='Security'; ID=4624,4625,4688; StartTime='%s'} -ErrorAction SilentlyContinue
			if ($events) {
				$events | ForEach-Object {
					$xml = [xml]$_.ToXml()
					$data = $xml.Event.EventData.Data
					
					$props = @{
						TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
						Id = $_.Id
						Message = $_.Message
					}

					if ($_.Id -eq 4688) {
						$props.Add("NewProcessName", ($data | Where-Object {$_.Name -eq 'NewProcessName'}).'#text')
						$props.Add("CommandLine", ($data | Where-Object {$_.Name -eq 'CommandLine'}).'#text')
						$props.Add("SubjectUserName", ($data | Where-Object {$_.Name -eq 'SubjectUserName'}).'#text')
						$props.Add("ParentProcessName", ($data | Where-Object {$_.Name -eq 'ParentProcessName'}).'#text')
					} else {
						$props.Add("IpAddress", ($data | Where-Object {$_.Name -eq 'IpAddress'}).'#text')
						$props.Add("TargetUserName", ($data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text')
						$props.Add("LogonType", ($data | Where-Object {$_.Name -eq 'LogonType'}).'#text')
					}
					
					[PSCustomObject]$props
				} | ConvertTo-Json -Depth 2
			}
		`, lastTime.Format("2006-01-02 15:04:05"))

			out, err := exec.Command("powershell", "-Command", psScript).Output()
			lastTime = time.Now()

			if err != nil || len(out) == 0 {
				continue
			}

			var events []interface{}
			if err := json.Unmarshal(out, &events); err != nil {
				var singleEvent interface{}
				if err := json.Unmarshal(out, &singleEvent); err == nil {
					events = append(events, singleEvent)
				}
			}

			if len(events) > 0 {
				log.Printf("Detected %d security events", len(events))
				eventBytes, _ := json.Marshal(events)

				data := createRawData(common.DataTypeSecurityLog, map[string]string{
					"count": fmt.Sprintf("%d", len(events)),
					"data":  string(eventBytes),
				})
				data.Data[0].Timestamp = time.Now().Unix()
				ch <- data
			}
		}
	}
}

func (c *SecurityLogCollector) Stop() {
	close(c.stopCh)
}
