package help

import (
	"fmt"
	"get-net/junge"
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
	DstIP     string //目的IP地址
	DstPort   int    //目的端口号
	Protocol  string //协议号
	TCPStatus string // TCP状态
	udpStatus string // UDP状态
}

// 把数据包的信息存入map中
// ID、源IP地址、源端口号、目的IP地址和目的IP地址和协议号

// WriteByteSessionMap 将数据包的信息存入 map 中,并生成ID
func WriteByteSessionMap(packet gopacket.Packet, currentID *int64, mu *sync.Mutex) SessionInfo {
	// 调用 JudgeID 函数，判断数据包是否属于之前的会话
	JudgeID(packet, currentID, &SessionMap)

	// 获取 IP 层
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)

		// 获取传输层
		transportLayer := packet.TransportLayer()
		if transportLayer != nil {
			// 判断传输层协议类型
			switch transportLayer.(type) {
			case *layers.TCP:
				tcp, _ := transportLayer.(*layers.TCP)
				// 构建唯一标识，这里使用字符串形式表示
				sessionKey := fmt.Sprintf("%s-%s-%d-%d-TCP", ip.SrcIP, ip.DstIP, tcp.SrcPort, tcp.DstPort)

				// 存入 map，值类型为 SessionInfo 结构体
				sessionInfo := SessionInfo{
					ID:        *currentID,
					SrcIP:     ip.SrcIP.String(),
					SrcPort:   int(tcp.SrcPort),
					DstIP:     ip.DstIP.String(),
					DstPort:   int(tcp.DstPort),
					Protocol:  "TCP",
					TCPStatus: junge.JungeTCPFinal(packet), // 获取TCP状态信息
				}
				SessionMap.Store(sessionKey, sessionInfo)
				return sessionInfo
			case *layers.UDP:
				udp, _ := transportLayer.(*layers.UDP)
				// 构建唯一标识，这里使用字符串形式表示
				sessionKey := fmt.Sprintf("%s-%s-%d-%d-UDP", ip.SrcIP, ip.DstIP, udp.SrcPort, udp.DstPort)

				// 存入 map，值类型为 SessionInfo 结构体
				sessionInfo := SessionInfo{
					ID:       *currentID,
					SrcIP:    ip.SrcIP.String(),
					SrcPort:  int(udp.SrcPort),
					DstIP:    ip.DstIP.String(),
					DstPort:  int(udp.DstPort),
					Protocol: "UDP",
				}
				SessionMap.Store(sessionKey, sessionInfo)
				return sessionInfo
			// 可以根据需要添加其他协议的处理
			default:
				// 其他协议的处理
			}
		}
	}
	return SessionInfo{}
}

// 判断数据包的会话是否重复，重复的话ID不变，否则ID加1
func JudgeID(packet gopacket.Packet, ID *int64, sessionMap *sync.Map) {
	// 获取 IP 层和 TCP 层
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	if ipLayer != nil && tcpLayer != nil {
		// 获取 IP 层和 TCP 层
		ip, _ := ipLayer.(*layers.IPv4)
		tcp, _ := tcpLayer.(*layers.TCP)

		// 创建会话键，在这里判断数据包是否重复
		sessionKey := fmt.Sprintf("%s-%s-%d-%d", ip.SrcIP, ip.DstIP, tcp.SrcPort, tcp.DstPort)

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
		} else {
			// 如果不是重复的数据包，分配一个新的 ID
			*ID++
			newID := *ID
			sessionMap.Store(sessionKey, SessionInfo{ID: newID})
			fmt.Printf("ID: %d\n", newID)
		}
	} else {
		// 输出调试信息
		fmt.Println("Not a TCP packet")
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
