package junge

import (
	"fmt"
	"get-net/help"
	"get-net/session"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

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

// 判断数据包的会话是否重复，并将数据包的信息存入map中
func JudgeIDAndWriteByteSessionMap(packet gopacket.Packet, ID *int64, sessionMap *sync.Map) session.SessionInfo {
	// 获取 IP 层
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		// 如果不是IPv4，尝试获取IPv6层
		ipLayer = packet.Layer(layers.LayerTypeIPv6)
		// if ipLayer == nil {
		// 	fmt.Println("Not an IPv4 or IPv6 packet")
		// 	return
		// }
	}
	// 获取传输层
	transportLayer := packet.TransportLayer()
	// if transportLayer == nil {
	// 	fmt.Println("Not a TCP or UDP packet")
	// 	return
	// }

	// 获取 IP 层和传输层
	var srcIP, dstIP net.IP
	switch ipLayer := ipLayer.(type) {
	case *layers.IPv4:
		srcIP = ipLayer.SrcIP
		dstIP = ipLayer.DstIP
	case *layers.IPv6:
		srcIP = ipLayer.SrcIP
		dstIP = ipLayer.DstIP
	}

	// 创建会话键，在这里判断数据包是否重复
	var sessionKey string
	switch transportLayer.(type) {
	case *layers.TCP:
		tcp, _ := transportLayer.(*layers.TCP)
		sessionKey = fmt.Sprintf("%s-%s-%d-%d", srcIP, dstIP, tcp.SrcPort, tcp.DstPort)
	case *layers.UDP:
		udp, _ := transportLayer.(*layers.UDP)
		sessionKey = fmt.Sprintf("%s-%s-%d-%d", srcIP, dstIP, udp.SrcPort, udp.DstPort)
	default:
		// fmt.Println("Not a TCP or UDP packet")
		// return
	}

	// 使用互斥锁确保在访问 sessionMap 时的原子性
	mu := &sync.Mutex{}
	mu.Lock()
	defer mu.Unlock()

	// 在循环外部调用一次 loadSessionInfo 函数，避免多次调用
	prevInfo, exists := help.LoadSessionInfo(sessionMap, sessionKey)

	// 如果会话键存在于映射中，表示数据包是重复的
	if exists {
		// 如果是重复的数据包，使用前面的信息
		fmt.Printf("数据包所属会话ID: %d (duplicate)\n", prevInfo.ID)
		// 将重复的ID存入SessionMap
		sessionMap.Store(sessionKey, session.SessionInfo{
			ID:             prevInfo.ID,
			SrcIP:          srcIP.String(),
			SrcPort:        help.GetSourcePort(transportLayer),
			DstIP:          dstIP.String(),
			DstPort:        help.GetDestinationPort(transportLayer),
			Protocol:       help.GetProtocolName(transportLayer),
			TCPStatus:      JungeTCPFinal(packet),
			SessionTraffic: session.SessionTrafficInfo{},
		})
		// 返回重复的SessionInfo
		return prevInfo
	} else {
		// 如果不是重复的数据包，分配一个新的 ID
		*ID++
		newID := *ID
		sessionMap.Store(sessionKey, session.SessionInfo{ID: newID})
		fmt.Printf("数据包所属会话ID: %d\n", newID)
		// 返回新分配的SessionInfo
		return session.SessionInfo{ID: newID}
	}
}
