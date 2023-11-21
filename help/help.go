package help

import (
	"fmt"
	"get-net/junge"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// 把数据包的信息存入map中
// ID、源MAC地址、源IP地址、源端口号、目的MAC地址、目的IP地址和目的IP地址和协议号

// WriteByteSessionMap 将数据包的信息存入 map 中,并生成ID
func WriteByteSessionMap(packet gopacket.Packet, currentID *int, mu *sync.Mutex) junge.SessionInfo {
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
				//分配唯一的ID
				mu.Lock()
				*currentID++
				mu.Unlock()
				// 存入 map，值类型为 SessionInfo 结构体
				junge.SessionMap[sessionKey] = junge.SessionInfo{
					ID:     *currentID,
					SrcMAC: packet.LinkLayer().LinkFlow().Src().String(),
					//q:看看报错，panic: runtime error: invalid memory address or nil pointer dereference
					// [signal SIGSEGV: segmentation violation code=0x2 addr=0x30 pc=0x100b36bb0]
					// goroutine 44 [running]:
					// get-net/help.WriteByteSessionMap({0x100bddb48, 0x140003c6000}, 0x10123e570, 0x14000480270)
					// 	/Users/siky/go/src/get-net/help/help.go:38 +0x230
					// main.CaptureTraffic({0x1400001024a, 0x3})
					// 	/Users/siky/go/src/get-net/main.go:73 +0x1ac
					// created by main.main in goroutine 1
					// 	/Users/siky/go/src/get-net/main.go:40 +0xe8
					// exit status 2
					//a：这里的packet.LinkLayer()是空的，所以会报错
					//q:为什么会是空的
					//a:因为这里的packet是从CaptureTraffic函数传过来的，而CaptureTraffic函数中的handle是从pcap.OpenLive函数传过来的
					//而pcap.OpenLive函数中的handle是从pcap.OpenLive函数传过来的
					SrcIP:     ip.SrcIP.String(),
					SrcPort:   int(tcp.SrcPort),
					DstMAC:    packet.LinkLayer().LinkFlow().Dst().String(),
					DstIP:     ip.DstIP.String(),
					DstPort:   int(tcp.DstPort),
					Protocol:  "TCP",
					TCPStatus: junge.JungeTCPFinal(packet), // 获取TCP状态信息
				}
			case *layers.UDP:
				udp, _ := transportLayer.(*layers.UDP)
				// 构建唯一标识，这里使用字符串形式表示
				sessionKey := fmt.Sprintf("%s-%s-%d-%d-UDP", ip.SrcIP, ip.DstIP, udp.SrcPort, udp.DstPort)
				// 分配唯一的ID，不能分配
				mu.Lock()
				*currentID++
				mu.Unlock()
				// 存入 map，值类型为 SessionInfo 结构体
				junge.SessionMap[sessionKey] = junge.SessionInfo{
					ID:       *currentID,
					SrcMAC:   packet.LinkLayer().LinkFlow().Src().String(),
					SrcIP:    ip.SrcIP.String(),
					SrcPort:  int(udp.SrcPort),
					DstMAC:   packet.LinkLayer().LinkFlow().Dst().String(),
					DstIP:    ip.DstIP.String(),
					DstPort:  int(udp.DstPort),
					Protocol: "UDP",
				}
			// 可以根据需要添加其他协议的处理
			default:
				// 其他协议的处理
			}
		}
	}
	return junge.SessionInfo{}
}
