package rule

import (
	"fmt"
	"testing"
)

func TestParseFile(t *testing.T) {
	// 指向实际的规则文件路径
	path := `d:\zhuomian\bishe (2)\test01\GoHIDS\suricata-rules-master\suricata-ids.rules`
	rules, err := ParseFile(path)
	if err != nil {
		t.Fatalf("Failed to parse file: %v", err)
	}

	fmt.Printf("Successfully parsed %d rules\n", len(rules))
	for i, r := range rules {
		if i < 5 { // Print first 5 rules
			fmt.Printf("Rule %d: %s\n", i+1, r)
		}
	}
}
