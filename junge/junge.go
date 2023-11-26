package junge

import (
	"fmt"
	"net"
	"sync"
	"view-net/help"
	"view-net/session"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var mu sync.Mutex

// 判断TCP是否终止，如果终止返回true，否则返回false
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
	}
	// 获取传输层
	transportLayer := packet.TransportLayer()

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
	}

	// 使用互斥锁确保在访问 sessionMap 时的原子性
	mu.Lock()
	defer mu.Unlock()

	// 在循环外部调用一次 loadSessionInfo 函数，避免多次调用
	prevInfo, exists := help.LoadSessionInfo(sessionMap, sessionKey)

	// 创建新的 SessionInfo 对象，用于存储当前数据包的信息
	newSessionInfo := session.SessionInfo{
		EndTime:            packet.Metadata().Timestamp,
		Bytes:              float64(len(packet.Data())),
		SrcIP:              srcIP.String(),
		SrcPort:            help.GetSourcePort(transportLayer),
		DstIP:              dstIP.String(),
		DstPort:            help.GetDestinationPort(transportLayer),
		Protocol:           help.GetProtocolName(transportLayer),
		TCPStatus:          JungeTCPFinal(packet),
		SessionUpTraffic:   0.0,
		SessionDownTraffic: 0.0,
	}

	// 如果会话键存在于映射中，表示数据包是重复的
	if exists {
		// 如果是重复的数据包，使用前面的信息
		fmt.Printf("数据包所属会话ID: %d (duplicate)\n", prevInfo.ID)

		// 复制之前的流量信息
		newSessionInfo.SessionUpTraffic = prevInfo.SessionUpTraffic + newSessionInfo.Bytes
		newSessionInfo.SessionDownTraffic = prevInfo.SessionDownTraffic + newSessionInfo.Bytes
		// 复制之前的 ID
		newSessionInfo.ID = prevInfo.ID
		// 复制之前的开始时间
		newSessionInfo.StartTime = prevInfo.StartTime
		// 更新映射
		sessionMap.Store(sessionKey, newSessionInfo)

	} else {
		// 如果不是重复的数据包，分配一个新的 ID
		*ID++
		newID := *ID
		newSessionInfo.ID = newID
		// 将当前数据包时间赋值给 SessionTime.StartTime
		newSessionInfo.StartTime = packet.Metadata().Timestamp
		// 将新的 SessionInfo 对象存入映射
		sessionMap.Store(sessionKey, newSessionInfo)
		fmt.Printf("数据包所属会话ID: %d\n", newID)

	}
	// 返回新的 SessionInfo 对象
	return newSessionInfo
}
