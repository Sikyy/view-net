package main

import (
	"fmt"
	"get-net/help"
	"get-net/junge"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var ID int = 0

func main() {

	// 初始化 SessionMap 使用 SessionInfo 结构体作为值类型
	// junge.SessionMap = make(map[string]junge.SessionInfo)

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

	for packet := range packetSource.Packets() {
		// 处理数据包

		//把信息存入map中，并生成ID
		SessionInfo := help.WriteByteSessionMap(packet, &ID, &mu)
		fmt.Println(packet)
		ProcessPacket(packet, SessionInfo)
	}
}

func ProcessPacket(packet gopacket.Packet, sessionInfo junge.SessionInfo) {
	// 在这里添加解析和整理数据包的逻辑
	// 你可能需要从 packet 中提取源地址、目标地址、协议、请求方法等信息
	// 并将这些信息按照你的要求整理成字符串

	// 以下是一个示例，你需要根据实际情况进行修改
	fmt.Printf("ID: %d\n", sessionInfo.ID)
	fmt.Printf("日期: %s\n", time.Now().Format("15:04:05"))
	fmt.Printf("客户端 状态: %s\n", junge.JungeTCPFinal(packet))
	fmt.Printf("策略: %s\n", "jp")                // 这里需要替换为实际的策略
	fmt.Printf("上传 下载: %d KB %d KB\n", 0, 0)    // 这里需要替换为实际的上传和下载数据量
	fmt.Printf("时长 方法: %d ms %s\n", 0, "HTTPS") // 这里需要替换为实际的时长和方法
	fmt.Printf("地址: %s\n", "example.com")       // 这里需要替换为实际的地址
	fmt.Println("----")
}
