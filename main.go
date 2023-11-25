package main

import (
	"fmt"
	"get-net/help"
	"get-net/junge"
	"get-net/session"
	"get-net/traffic"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var ID int64 = 0

func main() {

	// 获取本机所有网络接口的信息
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// 创建一个信号通道，用于接收系统信号
	stop := make(chan os.Signal, 1)
	// 监听系统信号，如果接收到系统信号，则停止捕获数据包
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	// 遍历所有网络接口
	for _, iface := range interfaces {
		fmt.Printf("Capturing traffic on interface %s...\n", iface.Name)
		// 在新的协程中捕获数据包
		go CaptureTraffic(iface.Name)
	}

	<-stop
	fmt.Println("Shutting down...")
}

// 进行数据包捕获和处理
func CaptureTraffic(ifaceName string) {

	// 定义一个互斥锁
	var mu sync.Mutex

	// 打开网络接口，开始捕获数据包
	handle, err := pcap.OpenLive(
		ifaceName,         // 网络接口名
		1600,              // 每个数据包的最大长度，1600 字节可以覆盖大多数以太网帧
		true,              // 设置为 true，表示开启混杂模式
		pcap.BlockForever, //表示永远阻塞，不会超时返回。而使用负数时间，可以认为是一个“非常大的超时时间”，基本上达到了永远阻塞的效果
	)
	if err != nil {
		fmt.Printf("Error opening interface %s: %v\n", ifaceName, err)
		return
	}
	// 保证程序退出时关闭网络接口
	defer handle.Close()

	// 创建一个数据包源，用于接收数据包。
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	// 获取本机的 IPv4 地址
	clientIP := help.GetClientIP()

	mu.Lock()
	defer mu.Unlock()

	for packet := range packetSource.Packets() {
		// 处理数据包
		//把信息存入map中，并生成ID
		SessionInfo := junge.JudgeIDAndWriteByteSessionMap(packet, &ID, &session.SessionMap)
		//处理数据的流量相关
		traffic.HandleTraffic(packet, clientIP, &SessionInfo, &session.SessionMap)
		//打印数据包原始信息
		fmt.Println(packet)
		//按照Surge请求查看器格式输出
		ProcessPacket(packet, &SessionInfo)
	}
}

// 按照Surge请求查看器格式输出
func ProcessPacket(packet gopacket.Packet, sessionInfo *session.SessionInfo) {
	// 在这里添加解析和整理数据包的逻辑
	if sessionInfo.ID == 0 {
		fmt.Println("Error: SessionInfo is empty")
		return
	}

	// 以下是一个示例，你需要根据实际情况进行修改
	fmt.Printf("会话ID: %d\n", sessionInfo.ID)
	fmt.Printf("日期: %s\n", time.Now().Format("15:04:05"))
	fmt.Printf("客户端 状态: %s\n", junge.JungeTCPFinal(packet))
	fmt.Printf("策略: %s\n", "Normal") // 这里需要替换为实际的策略
	fmt.Printf("上传: %s 下载: %s\n", traffic.FormatBytes(sessionInfo.SessionUpTraffic), traffic.FormatBytes(sessionInfo.SessionDownTraffic))
	fmt.Printf("时长: %d ms, 方法: %s\n", sessionInfo.EndTime.Sub(sessionInfo.StartTime).Milliseconds(), "HTTPS")
	fmt.Printf("开始时间: %s, 结束时间: %s\n", sessionInfo.StartTime, sessionInfo.EndTime)
	fmt.Printf("地址: %s\n", "example.com") // 这里需要替换为实际的地址
	fmt.Println("----")
}
