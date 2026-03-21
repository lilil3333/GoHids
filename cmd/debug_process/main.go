package main

import (
	"fmt"
	"github.com/shirou/gopsutil/v3/process"
)

func main() {
	fmt.Println("Scanning processes to reproduce 'empty info' issue...")
	
	procs, err := process.Processes()
	if err != nil {
		fmt.Printf("Error getting processes: %v\n", err)
		return
	}

	countEmpty := 0
	countPermission := 0

	for _, p := range procs {
		pid := p.Pid
		
		// 模拟 ProcessCollector 中的行为：忽略错误
		name, errName := p.Name()
		cmdline, errCmd := p.Cmdline()
		
		if name == "" {
			// 如果 Name 为空，我们看看具体报了什么错
			fmt.Printf("[PID: %d] Name is empty. Error: %v\n", pid, errName)
			countEmpty++
			if errName != nil && (errName.Error() == "access denied" || errName.Error() == "Access is denied.") {
				countPermission++
			}
		} else {
			// 如果 Cmdline 为空但 Name 不为空，通常也是权限或者系统进程
			if cmdline == "" {
				// 减少输出噪音，只打印几个示例
				if countEmpty < 5 {
					fmt.Printf("[PID: %d] Name: %s, Cmdline is empty. Error: %v\n", pid, name, errCmd)
				}
			}
		}
	}
	
	fmt.Printf("\nSummary:\n")
	fmt.Printf("Total Processes: %d\n", len(procs))
	fmt.Printf("Processes with empty Name: %d\n", countEmpty)
}
