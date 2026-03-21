package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// 定义简单的翻译映射表
// 关键词匹配，优先匹配长词
var translationMap = map[string]string{
	"CobaltStrike login server": "CobaltStrike 登录服务器检测",
	"CobaltStrike download.windowsupdate.com C2 Profile": "CobaltStrike 伪造Windows更新C2通信",
	"CobaltStrike HTTP beacon response": "CobaltStrike HTTP Beacon 响应",
	"CobaltStrike ARP Scan module": "CobaltStrike ARP 扫描模块",
	"CobatlStrikt team servers 200 OK Space": "CobaltStrike 团队服务器特征响应",
	"CobaltStrike C2 Server": "CobaltStrike C2 服务器通信",
	"Observed DNS Query to public CryptoMining pool Domain": "检测到向公共矿池域名的DNS查询",
	"Cryptocurrency Miner Check By Submit": "检测到加密货币矿机提交结果",
	"Weevely PHP Backdoor Response": "Weevely PHP 后门响应",
	"webshell_caidao_php": "Webshell 菜刀 PHP 连接",
	"Apache Nifi API RCE": "Apache Nifi API 远程代码执行漏洞",
	"CVE-2020-10148": "CVE-2020-10148 漏洞利用尝试",
	"CVE-2020-12146": "CVE-2020-12146 漏洞利用尝试",
	"CVE-2020-13942": "CVE-2020-13942 漏洞利用尝试",
	"CVE-2020-14750": "CVE-2020-14750 漏洞利用尝试",
	"CVE-2020-16846": "CVE-2020-16846 漏洞利用尝试",
	"CVE-2020-17132": "CVE-2020-17132 漏洞利用尝试",
	"CVE-2020-17141": "CVE-2020-17141 漏洞利用尝试",
	"CVE-2020-17143": "CVE-2020-17143 漏洞利用尝试",
	"CVE-2020-26073": "CVE-2020-26073 漏洞利用尝试",
	"CVE-2020-27130": "CVE-2020-27130 漏洞利用尝试",
	"CVE-2020-27131": "CVE-2020-27131 漏洞利用尝试",
	"CVE-2020-3984": "CVE-2020-3984 漏洞利用尝试",
	"CVE-2020-4000": "CVE-2020-4000 漏洞利用尝试",
	"CVE-2020-4001": "CVE-2020-4001 漏洞利用尝试",
	"CVE-2020-8209": "CVE-2020-8209 漏洞利用尝试",
	"CVE-2020-8271": "CVE-2020-8271 漏洞利用尝试",
	"CVE-2021-2109": "CVE-2021-2109 漏洞利用尝试",
	"DNS Tunneling": "DNS 隧道通信行为",
	"ICMP Tunneling": "ICMP 隧道通信行为",
	"Metasploit": "Metasploit 攻击框架特征",
	"PowerShell Empire": "PowerShell Empire C2 通信",
	"MySQL general log write file": "MySQL 通用日志写入文件尝试 (可能用于Webshell写入)",
}

// 模糊匹配规则
var fuzzyRules = []struct {
	Pattern string
	Replace string
}{
	{`(?i)CobaltStrike`, "CobaltStrike C2 恶意通信"},
	{`(?i)CryptoMining`, "加密货币挖矿行为"},
	{`(?i)Webshell`, "Webshell 恶意连接"},
	{`(?i)Backdoor`, "后门程序通信"},
	{`(?i)RCE`, "远程代码执行(RCE)攻击"},
	{`(?i)SQL Injection`, "SQL注入攻击"},
	{`(?i)XSS`, "跨站脚本(XSS)攻击"},
}

var msgRegex = regexp.MustCompile(`msg:\s*"(.*?)";`)

func main() {
	rootDir := `d:\zhuomian\bishe (2)\test01\GoHIDS\suricata-rules-master`
	
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".rules") {
			fmt.Printf("Processing: %s\n", path)
			processFile(path)
		}
		return nil
	})
	
	if err != nil {
		fmt.Printf("Error walking path: %v\n", err)
	}
}

func processFile(path string) {
	file, err := os.Open(path)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		translatedLine := translateLine(line)
		lines = append(lines, translatedLine)
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error scanning file: %v\n", err)
		return
	}

	// Write back
	output := strings.Join(lines, "\n")
	err = ioutil.WriteFile(path, []byte(output), 0644)
	if err != nil {
		fmt.Printf("Error writing file: %v\n", err)
	}
}

func translateLine(line string) string {
	matches := msgRegex.FindStringSubmatch(line)
	if len(matches) < 2 {
		return line
	}
	
	originalMsg := matches[1]
	
	// 1. 精确匹配
	if val, ok := translationMap[originalMsg]; ok {
		return strings.Replace(line, fmt.Sprintf(`msg: "%s"`, originalMsg), fmt.Sprintf(`msg: "%s"`, val), 1)
	}
	
	// 2. 部分匹配 (目录/前缀)
	for k, v := range translationMap {
		if strings.Contains(originalMsg, k) {
			return strings.Replace(line, fmt.Sprintf(`msg: "%s"`, originalMsg), fmt.Sprintf(`msg: "%s"`, v), 1)
		}
	}

	// 3. 模糊正则匹配
	for _, rule := range fuzzyRules {
		matched, _ := regexp.MatchString(rule.Pattern, originalMsg)
		if matched {
			// 保留原意但增加中文前缀
			newMsg := fmt.Sprintf("检测到 %s (%s)", rule.Replace, originalMsg)
			return strings.Replace(line, fmt.Sprintf(`msg: "%s"`, originalMsg), fmt.Sprintf(`msg: "%s"`, newMsg), 1)
		}
	}
	
	// 4. 通用兜底 (如果未匹配到，则不修改，避免乱改)
	return line
}
