package rule

import "fmt"

type Rule struct {
	Raw        string
	Action     string
	Protocol   string
	SrcIP      string
	SrcPort    string
	DstIP      string
	DstPort    string
	Msg        string
	Contents   []string // 提取出的关键词 (纯文本)
	SID        string
	ClassType  string
	Flow       string            // New: flow keyword (e.g. "established,to_server")
	Meta       map[string]string // New: metadata for extension (e.g. "process_path", "user")
	References []string          // New: reference links
}

func (r *Rule) String() string {
	return fmt.Sprintf("[SID:%s] %s (Keywords: %v, Flow: %s)", r.SID, r.Msg, r.Contents, r.Flow)
}
