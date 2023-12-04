package junge

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
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
		// 复制之前的 Host
		newSessionInfo.Host = prevInfo.Host
		// 复制之前的 Method
		newSessionInfo.Method = prevInfo.Method
		// 更新映射
		sessionMap.Store(sessionKey, newSessionInfo)

	} else {
		// 如果不是重复的数据包，分配一个新的 ID
		*ID++
		newID := *ID
		newSessionInfo.ID = newID
		// 将当前数据包时间赋值给 SessionTime.StartTime
		newSessionInfo.StartTime = packet.Metadata().Timestamp
		// 如果当前数据包的Host 和 Method不为空，将当前数据包的 Host 和 Method 赋值给 SessionInfo
		if host, method := HandleHTTPPorHTTPSPacket(packet); host != "" && method != "" {
			newSessionInfo.Host = host
			newSessionInfo.Method = method
		}
		// 将新的 SessionInfo 对象存入映射
		sessionMap.Store(sessionKey, newSessionInfo)
		fmt.Printf("数据包所属会话ID: %d\n", newID)

	}
	// 返回新的 SessionInfo 对象
	return newSessionInfo
}

func HandleHTTPPorHTTPSPacket(packet gopacket.Packet) (string, string) {
	var host, method string
	// 获取以太网头部信息
	ethernetPacket, _ := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	// 获取 TCP 层
	tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	// 获取 UDP 层
	udp, _ := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)

	// 获取 IPv4 层
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		// 如果不是 IPv4，尝试获取 IPv6 层
		ipLayer = packet.Layer(layers.LayerTypeIPv6)
	}

	var srcIP, dstIP net.IP
	var protocol layers.IPProtocol

	switch ipLayer := ipLayer.(type) {
	case *layers.IPv4:
		srcIP = ipLayer.SrcIP
		dstIP = ipLayer.DstIP
		protocol = ipLayer.Protocol
	case *layers.IPv6:
		srcIP = ipLayer.SrcIP
		dstIP = ipLayer.DstIP
		protocol = ipLayer.NextHeader
	}

	// 处理 TCP 流量
	if tcp != nil {
		if isHTTPS(packet) {
			fmt.Println("--------------------------------------------------------------------")
			fmt.Println("方法为:HTTPS")
			fmt.Printf("确认号: %d\n", tcp.Ack)
			fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
			fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
			fmt.Printf("From %s to %s\n", srcIP, dstIP)
			fmt.Println("Protocol: ", protocol)
			fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
			fmt.Println("Sequence number: ", tcp.Seq)
			host = "HTTPS:443"
			method = "HTTPS"
		} else if isHTTP(packet) {
			applicationLayer := packet.ApplicationLayer()
			payload := string(applicationLayer.Payload())
			fmt.Println("--------------------------------------------------------------------")
			fmt.Println("方法为:HTTP")
			reg := regexp.MustCompile(`(?s)(GET|POST|PUT|DELETE|HEAD|TRACE|OPTIONS) (.*?) HTTP.*Host: (.*?)\n`)
			if reg == nil {
				fmt.Println("MustCompile err")
				return "MustCompile", "err"
			}
			result := reg.FindStringSubmatch(payload)
			if len(result) == 4 {
				result[2] = strings.TrimSpace(result[2])
				result[3] = strings.TrimSpace(result[3])
				url := "http://" + result[3] + result[2]
				fmt.Println("--------------------------------------------------------------------")
				fmt.Println("请求头:", result[0])
				fmt.Println("请求方法: ", result[1])
				fmt.Printf("确认号: %d\n", tcp.Ack)
				fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
				fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
				fmt.Printf("From %s to %s\n", srcIP, dstIP)
				fmt.Println("Protocol: ", protocol)
				fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
				fmt.Println("Sequence number: ", tcp.Seq)
				fmt.Println("url:", url)
				fmt.Println("host:", result[3])
				host = result[3]
				method = result[1]
			}
		} else {
			fmt.Println("--------------------------------------------------------------------")
			fmt.Println("方法为:TCP")
			// fmt.Printf("源 MAC 地址: %s\n", ethernetPacket.SrcMAC)
			// fmt.Printf("目标 MAC 地址: %s\n", ethernetPacket.DstMAC)
			fmt.Printf("确认号: %d\n", tcp.Ack)
			fmt.Printf("从 %s 到 %s\n", srcIP, dstIP)
			fmt.Printf("协议: %s\n", protocol)
			fmt.Printf("从端口 %d 到端口 %d\n", tcp.SrcPort, tcp.DstPort)
			fmt.Printf("序列号: %d\n", tcp.Seq)

			// 获取本地主机名
			hostname, err := os.Hostname()
			if err == nil {
				fmt.Printf("本地主机名: %s\n", hostname)
				// 显示端口号
				fmt.Printf("目标端口: %d\n", tcp.DstPort)

				host = fmt.Sprintf("%s:%d", hostname, tcp.DstPort)
			} else {
				fmt.Printf("无法获取本地主机名: %v\n", err)
				host = fmt.Sprintf("N/A:%d", tcp.DstPort)
			}

			// 显示端口号
			fmt.Printf("目标端口: %d\n", tcp.DstPort)

			host = fmt.Sprintf("%s:%d", hostname, tcp.DstPort)
			method = "TCP"
		}
		return host, method

	} else if udp != nil {
		// 处理 UDP 流量
		fmt.Println("--------------------------------------------------------------------")
		fmt.Println("方法为:UDP")
		// 处理 UDP 流量的逻辑，你可以根据需要进行修改
		// ...
		// 检查是否有源和目标端口
		if udp.SrcPort != layers.UDPPort(0) && udp.DstPort != layers.UDPPort(0) {
			fmt.Printf("从端口 %d 到端口 %d\n", udp.SrcPort, udp.DstPort)
			host = fmt.Sprintf("%s:%d", dstIP, udp.DstPort)
		} else {
			fmt.Println("UDP 没有源或目标端口信息")
			host = "N/A"
		}

		method = "UDP"
	} else {
		fmt.Println("不是 TCP 或 UDP 流量")
		host = "N/A"
		method = "N/A"
	}

	return host, method
}

// 监测是否是HTTPS，先检测端口，再检测layers.LayerTypeTLS是否包含TLS握手
func isHTTPS(packet gopacket.Packet) bool {
	// 分析数据包
	transportLayer := packet.TransportLayer()

	// 检查是否为 TCP 协议
	if transportLayer != nil && transportLayer.LayerType() == layers.LayerTypeTCP {
		tcp := transportLayer.(*layers.TCP)

		// 检查是否为 HTTPS 流量（默认端口为 443）
		if tcp.DstPort == 443 || tcp.SrcPort == 443 {
			fmt.Println("Detected HTTPS traffic.")
			return true
		}
	}
	return false
}

// 监测是否是HTTP，先检测是否是TCP，再检测是否包含HTTP请求方法
func isHTTP(packet gopacket.Packet) bool {
	// 分析数据包
	transportLayer := packet.TransportLayer()

	// 检查是否为TCP流量
	if transportLayer != nil && transportLayer.LayerType() == layers.LayerTypeTCP {
		tcp := transportLayer.(*layers.TCP)

		// 检查是否为HTTP端口
		if tcp.DstPort == 80 {
			applicationLayer := packet.ApplicationLayer()

			// 检查是否包含HTTP请求方法
			if applicationLayer != nil {
				payload := string(applicationLayer.Payload())
				if strings.HasPrefix(payload, "GET") || strings.HasPrefix(payload, "POST") || strings.HasPrefix(payload, "PUT") || strings.HasPrefix(payload, "DELETE") || strings.HasPrefix(payload, "HEAD") || strings.HasPrefix(payload, "TRACE") || strings.HasPrefix(payload, "OPTIONS") {
					return true
				}
			}
		}
	}
	return false
}
