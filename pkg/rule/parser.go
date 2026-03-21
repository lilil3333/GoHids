package rule

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

// 简单的正则来匹配 header 和 options
// alert tcp ... (...)
// 使用宽松的空格匹配
var ruleRegex = regexp.MustCompile(`^(?P<action>[a-zA-Z]+)\s+(?P<proto>[a-zA-Z0-9]+)\s+(?P<src_ip>\S+)\s+(?P<src_port>\S+)\s+->\s+(?P<dst_ip>\S+)\s+(?P<dst_port>\S+)\s+\((?P<options>.*)\)`)

// 匹配 options 中的字段
var msgRegex = regexp.MustCompile(`msg:\s*"(.*?)";`)
var contentRegex = regexp.MustCompile(`content:\s*"(.*?)";`)
var sidRegex = regexp.MustCompile(`sid:\s*(\d+);`)
var classTypeRegex = regexp.MustCompile(`classtype:\s*([a-zA-Z0-9-_]+);`)
var flowRegex = regexp.MustCompile(`flow:\s*([a-zA-Z0-9_,]+);`)
var metadataRegex = regexp.MustCompile(`metadata:\s*(.*?);`)
var referenceRegex = regexp.MustCompile(`reference:\s*(.*?);`)

func ParseFile(path string) ([]*Rule, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var rules []*Rule
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if r := ParseLine(line); r != nil {
			rules = append(rules, r)
		}
	}
	return rules, scanner.Err()
}

func ParseLine(line string) *Rule {
	matches := ruleRegex.FindStringSubmatch(line)
	if matches == nil {
		return nil
	}

	// 简单的索引映射，因为 FindStringSubmatch 返回包含全匹配的切片
	// 0: full, 1: action, 2: proto, 3: src_ip, 4: src_port, 5: dst_ip, 6: dst_port, 7: options
	if len(matches) < 8 {
		return nil
	}

	r := &Rule{
		Raw:      line,
		Action:   matches[1],
		Protocol: matches[2],
		SrcIP:    matches[3],
		SrcPort:  matches[4],
		DstIP:    matches[5],
		DstPort:  matches[6],
	}

	options := matches[7]

	// Extract Msg
	if m := msgRegex.FindStringSubmatch(options); len(m) > 1 {
		r.Msg = m[1]
	}

	// Extract Contents
	cMatches := contentRegex.FindAllStringSubmatch(options, -1)
	for _, cm := range cMatches {
		if len(cm) > 1 {
			val := cm[1]
			// 如果包含 | (hex delimiter)，我们尝试只保留非 hex 部分，或者直接忽略
			// 这里策略：如果全是 hex (e.g. |00 01|)，忽略
			// 如果是混合 (e.g. |00|abc)，保留 abc
			// 简化策略：只要包含 | 且不是简单的边界（Suricata 有时用 | 来包裹 hex），就先忽略，只取纯文本 content
			// 实际上很多规则是 content:"User-Agent"; 这种最有用
			if !strings.Contains(val, "|") {
				r.Contents = append(r.Contents, val)
			}
		}
	}

	// Extract SID
	if m := sidRegex.FindStringSubmatch(options); len(m) > 1 {
		r.SID = m[1]
	}

	// Extract ClassType
	if m := classTypeRegex.FindStringSubmatch(options); len(m) > 1 {
		r.ClassType = m[1]
	}

	// Extract Flow
	if m := flowRegex.FindStringSubmatch(options); len(m) > 1 {
		r.Flow = m[1]
	}

	// Extract Metadata
	r.Meta = make(map[string]string)
	if m := metadataRegex.FindAllStringSubmatch(options, -1); len(m) > 0 {
		for _, meta := range m {
			if len(meta) > 1 {
				// metadata format: key value, key value
				parts := strings.Split(meta[1], ",")
				for _, part := range parts {
					kv := strings.Fields(strings.TrimSpace(part))
					if len(kv) >= 2 {
						r.Meta[kv[0]] = strings.Join(kv[1:], " ")
					} else if len(kv) == 1 {
						r.Meta[kv[0]] = "true"
					}
				}
			}
		}
	}

	// Extract References
	if m := referenceRegex.FindAllStringSubmatch(options, -1); len(m) > 0 {
		for _, ref := range m {
			if len(ref) > 1 {
				r.References = append(r.References, ref[1])
			}
		}
	}

	return r
}
