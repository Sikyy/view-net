package junge

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// 定义 SessionInfo 结构体，用于存储会话信息
type SessionInfo struct {
	ID        int    //会话ID
	SrcMAC    string //源MAC地址
	SrcIP     string //源IP地址
	SrcPort   int    //源端口号
	DstMAC    string //目的MAC地址
	DstIP     string //目的IP地址
	DstPort   int    //目的端口号
	Protocol  string //协议号
	TCPStatus string // TCP状态
	udpStatus string // UDP状态
}

// 初始化 SessionMap 使用 SessionInfo 结构体作为值类型
var SessionMap = make(map[string]SessionInfo)

//判断TCP是否终止，如果终止返回true，否则返回false

func JungeTCPFinal(packet gopacket.Packet) string {
	// 获取 TCP 层
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		// 获取 TCP 层
		tcp, _ := tcpLayer.(*layers.TCP)
		// 判断是否是终止
		if tcp.FIN == true {
			return "已完成"
		}
	}
	// 如果没有找到 FIN 标志，返回 false
	return "活跃"
}

// 判断数据包的会话是否重复，重复的话ID不变，否则ID加1
func JudgeID(packet gopacket.Packet, ID *int, sessionMap map[string]SessionInfo) {
	// 获取 IP 层和 TCP 层
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	if ipLayer != nil && tcpLayer != nil {
		// 获取 IP 层和 TCP 层
		ip, _ := ipLayer.(*layers.IPv4)
		tcp, _ := tcpLayer.(*layers.TCP)

		// 创建会话键，在这里判断数据包是否重复
		sessionKey := fmt.Sprintf("%s-%s-%d-%d", ip.SrcIP, ip.DstIP, tcp.SrcPort, tcp.DstPort)
		// 如果会话键存在于映射中，表示数据包是重复的
		if prevInfo, exists := sessionMap[sessionKey]; exists {
			// 如果是重复的数据包，使用前面的信息
			fmt.Printf("ID: %d (duplicate)\n", prevInfo.ID)
		} else {
			// 如果不是重复的数据包，分配一个新的 ID
			*ID++

			// 创建新的 SessionInfo 结构体并存入 sessionMap
			newInfo := SessionInfo{
				ID:       *ID,
				SrcIP:    ip.SrcIP.String(),
				DstIP:    ip.DstIP.String(),
				SrcPort:  int(tcp.SrcPort),
				DstPort:  int(tcp.DstPort),
				Protocol: "TCP", // 如果需要判断其他协议，请在此处修改
				// 其他字段按照需要补充
			}

			sessionMap[sessionKey] = newInfo

			// 输出调试信息
			fmt.Printf("ID: %d\n", *ID)
			fmt.Printf("SrcIP: %s, DstIP: %s, SrcPort: %d, DstPort: %d\n", ip.SrcIP, ip.DstIP, tcp.SrcPort, tcp.DstPort)
		}
	} else {
		// 输出调试信息
		fmt.Println("Not a TCP packet")
	}
}
