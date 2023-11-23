package main

import (
	"fmt"

	"github.com/shirou/gopsutil/process"
)

func main() {
	// 获取所有进程的信息
	processes, err := process.Processes()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// 遍历每个进程并打印PID和名字
	for _, proc := range processes {
		pid := proc.Pid
		name, err := proc.Name()
		if err != nil {
			// 处理错误，跳过此进程
			continue
		}

		fmt.Printf("PID: %d, Name: %s\n", pid, name)
	}
}
