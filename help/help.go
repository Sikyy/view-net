package help

import (
	"fmt"
	"get-net/junge"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// 在 help 包中定义一个全局的 sync.Map
var SessionMap sync.Map

type SessionInfo struct {
	ID int64 //会话ID
	// SrcMAC    string //源MAC地址
	SrcIP   string //源IP地址
	SrcPort int    //源端口号
	// DstMAC    string //目的MAC地址
	DstIP       string //目的IP地址
	DstPort     int    //目的端口号
	Protocol    string //协议号
	TCPStatus   string // TCP状态
	udpStatus   string // UDP状态
	UpTraffic   int64  //上行流量
	DownTraffic int64  //下行流量
}

// 把数据包的信息存入map中
// ID、源IP地址、源端口号、目的IP地址和目的IP地址和协议号

// WriteByteSessionMap 将数据包的信息存入 map 中,并生成ID
func WriteByteSessionMap(packet gopacket.Packet, currentID *int64, mu *sync.Mutex) SessionInfo {
	// 调用 JudgeID 函数，判断数据包是否属于之前的会话
	return JudgeID(packet, currentID, &SessionMap)

	// // 获取 IP 层
	// ipLayer := packet.Layer(layers.LayerTypeIPv4)
	// if ipLayer != nil {
	// 	ip, _ := ipLayer.(*layers.IPv4)

	// 	// 获取传输层
	// 	transportLayer := packet.TransportLayer()
	// 	if transportLayer != nil {
	// 		// 判断传输层协议类型
	// 		switch transportLayer.(type) {
	// 		case *layers.TCP:
	// 			tcp, _ := transportLayer.(*layers.TCP)
	// 			// 构建唯一标识，这里使用字符串形式表示
	// 			sessionKey := fmt.Sprintf("%s-%s-%d-%d-TCP", ip.SrcIP, ip.DstIP, tcp.SrcPort, tcp.DstPort)

	// 			// 存入 map，值类型为 SessionInfo 结构体
	// 			sessionInfo := SessionInfo{
	// 				ID:        *currentID,
	// 				SrcIP:     ip.SrcIP.String(),
	// 				SrcPort:   int(tcp.SrcPort),
	// 				DstIP:     ip.DstIP.String(),
	// 				DstPort:   int(tcp.DstPort),
	// 				Protocol:  "TCP",
	// 				TCPStatus: junge.JungeTCPFinal(packet), // 获取TCP状态信息
	// 			}
	// 			SessionMap.Store(sessionKey, sessionInfo)
	// 			return sessionInfo
	// 		case *layers.UDP:
	// 			udp, _ := transportLayer.(*layers.UDP)
	// 			// 构建唯一标识，这里使用字符串形式表示
	// 			sessionKey := fmt.Sprintf("%s-%s-%d-%d-UDP", ip.SrcIP, ip.DstIP, udp.SrcPort, udp.DstPort)

	// 			// 存入 map，值类型为 SessionInfo 结构体
	// 			sessionInfo := SessionInfo{
	// 				ID:       *currentID,
	// 				SrcIP:    ip.SrcIP.String(),
	// 				SrcPort:  int(udp.SrcPort),
	// 				DstIP:    ip.DstIP.String(),
	// 				DstPort:  int(udp.DstPort),
	// 				Protocol: "UDP",
	// 			}
	// 			SessionMap.Store(sessionKey, sessionInfo)
	// 			return sessionInfo
	// 		// 可以根据需要添加其他协议的处理
	// 		default:
	// 			// 其他协议的处理
	// 		}
	// 	}
	// }
	// return SessionInfo{}
}

// 判断数据包的会话是否重复，重复的话ID不变，否则ID加1
func JudgeID(packet gopacket.Packet, ID *int64, sessionMap *sync.Map) SessionInfo {
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
	prevInfo, exists := loadSessionInfo(sessionMap, sessionKey)

	// 如果会话键存在于映射中，表示数据包是重复的
	if exists {
		// 如果是重复的数据包，使用前面的信息
		fmt.Printf("ID: %d (duplicate)\n", prevInfo.ID)
		// 将重复的ID存入SessionMap
		sessionMap.Store(sessionKey, SessionInfo{
			ID:        prevInfo.ID,
			SrcIP:     srcIP.String(),
			SrcPort:   getSourcePort(transportLayer),
			DstIP:     dstIP.String(),
			DstPort:   getDestinationPort(transportLayer),
			Protocol:  getProtocolName(transportLayer),
			TCPStatus: junge.JungeTCPFinal(packet),
		})
		// 返回重复的SessionInfo
		return prevInfo
	} else {
		// 如果不是重复的数据包，分配一个新的 ID
		*ID++
		newID := *ID
		sessionMap.Store(sessionKey, SessionInfo{ID: newID})
		fmt.Printf("ID: %d\n", newID)
		// 返回新分配的SessionInfo
		return SessionInfo{ID: newID}
	}
}

// 使用 sync.Map 安全地加载 SessionInfo
func loadSessionInfo(sessionMap *sync.Map, key string) (SessionInfo, bool) {
	value, ok := sessionMap.Load(key)
	if !ok {
		return SessionInfo{}, false
	}
	return value.(SessionInfo), true
}

// 使用 sync.Map 安全地存储 SessionInfo
func storeSessionInfo(sessionMap *sync.Map, key string, value SessionInfo) {
	sessionMap.Store(key, value)
}

// 辅助函数，根据协议获取协议名称
func getProtocolName(transportLayer gopacket.TransportLayer) string {
	switch transportLayer.(type) {
	case *layers.TCP:
		return "TCP"
	case *layers.UDP:
		return "UDP"
	default:
		return "Unknown"
	}
}

// 辅助函数，获取源端口
func getSourcePort(transportLayer gopacket.TransportLayer) int {
	switch transportLayer := transportLayer.(type) {
	case *layers.TCP:
		return int(transportLayer.SrcPort)
	case *layers.UDP:
		return int(transportLayer.SrcPort)
	default:
		return 0
	}
}

// 辅助函数，获取目标端口
func getDestinationPort(transportLayer gopacket.TransportLayer) int {
	switch transportLayer := transportLayer.(type) {
	case *layers.TCP:
		return int(transportLayer.DstPort)
	case *layers.UDP:
		return int(transportLayer.DstPort)
	default:
		return 0
	}
}
