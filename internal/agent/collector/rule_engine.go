package collector

import (
	"gohids/pkg/rule"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	engine *RuleEngine
	once   sync.Once
)

type RuleEngine struct {
	Rules []*rule.Rule
}

// GetRuleEngine 单例模式获取规则引擎
func GetRuleEngine() *RuleEngine {
	once.Do(func() {
		// 扫描整个 suricata-rules-master 目录
		rootDir := `d:\zhuomian\bishe (2)\test01\GoHIDS\suricata-rules-master`
		var allRules []*rule.Rule

		err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			// 只加载 .rules 文件
			if !info.IsDir() && strings.HasSuffix(path, ".rules") {
				rules, err := rule.ParseFile(path)
				if err != nil {
					log.Printf("[RuleEngine] Warning: Failed to parse %s: %v", path, err)
				} else {
					allRules = append(allRules, rules...)
				}
			}
			return nil
		})

		if err != nil {
			log.Printf("[RuleEngine] Error walking directory: %v", err)
		}

		engine = &RuleEngine{Rules: allRules}
		log.Printf("[RuleEngine] Initialization complete. Loaded %d rules total.", len(allRules))
	})
	return engine
}

// MatchProcess 检查进程命令行是否命中规则
// 返回命中的第一条规则，如果没有命中返回 nil
func (e *RuleEngine) MatchProcess(info ProcessInfo) *rule.Rule {
	cmdline := info.Cmdline
	if cmdline == "" {
		return nil
	}

	lowerCmd := strings.ToLower(cmdline)

	for _, r := range e.Rules {
		// 只有当规则包含内容关键词时才进行匹配
		if len(r.Contents) == 0 {
			continue
		}

		// 0. Optimization: Skip network-only rules for process matching
		// If it's an HTTP/DNS/TLS rule and has no process-specific metadata, skip it.
		isNetworkProto := r.Protocol == "http" || r.Protocol == "dns" || r.Protocol == "tls" || r.Protocol == "ssh"
		hasProcessMeta := false
		if r.Meta != nil {
			_, hasPath := r.Meta["process_path"]
			_, hasUser := r.Meta["user"]
			hasProcessMeta = hasPath || hasUser
		}
		if isNetworkProto && !hasProcessMeta {
			continue
		}

		// 1. Keyword Match (Cmdline)
		allMatch := true
		hasStrongKeyword := false
		for _, k := range r.Contents {
			// Avoid weak keywords like "200", "GET", "http" unless accompanied by others
			if len(k) > 3 {
				hasStrongKeyword = true
			}
			// 将规则关键词也转为小写进行匹配（忽略大小写）
			if !strings.Contains(lowerCmd, strings.ToLower(k)) {
				allMatch = false
				break
			}
		}

		// If all keywords match, but they are all weak (e.g. just "200") and no meta context, skip to avoid FPs
		if !allMatch || (!hasStrongKeyword && !hasProcessMeta) {
			continue
		}

		// 2. Metadata Match (Extension: process_path, user)
		if r.Meta != nil {
			if targetPath, ok := r.Meta["process_path"]; ok {
				if !strings.Contains(strings.ToLower(info.Path), strings.ToLower(targetPath)) {
					continue
				}
			}
			if targetUser, ok := r.Meta["user"]; ok {
				if !strings.Contains(strings.ToLower(info.Username), strings.ToLower(targetUser)) {
					continue
				}
			}
		}

		return r
	}
	return nil
}
