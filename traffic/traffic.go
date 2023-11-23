package traffic

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// 统计流量总数
func CountTraffic(packet gopacket.Packet) {

}

//上行部分

func CountUpTraffic(packet gopacket.Packet) {
	//用JudgeUpOrDown来判断是上行还是下行
	//是上行就记入
	// packetSize := packet.Metadata().CaptureLength
}

//下行部分

func CountDownTraffic(packet gopacket.Packet) {
	//用JudgeUpOrDown来判断是上行还是下行
	//是下行就记入
	// packetSize := packet.Metadata().CaptureLength
	// JudgeUpOrDown(packet, clientIP)
}

// 传入一个定义的客户端的 IPv4 或 IPv6 地址，判断数据包是上行还是下行
func JudgeUpOrDown(packet gopacket.Packet, clientIP string) bool {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		// IPv4 数据包
		ip, _ := ipLayer.(*layers.IPv4)
		// 判断是否是上行流量，DstIP 是目的地址，SrcIP 是源地址，因为IPv4地址是单向的，所以这里判断的是源地址
		if ip.SrcIP.String() == clientIP {
			fmt.Println("This is upstream traffic.")
			return true
		} else {
			fmt.Println("This is downstream traffic.")
			return false
		}
	}

	//如果没有获取到 IPv4 层
	// 尝试获取 IPv6 层
	ip6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ip6Layer != nil {
		// IPv6 数据包
		ip6, _ := ip6Layer.(*layers.IPv6)
		// 判断是否是上行流量，DstIP 是目的地址，SrcIP 是源地址，因为IPv6地址是双向的，所以这里判断的是目的地址
		if ip6.DstIP.String() == clientIP {
			fmt.Println("This is upstream traffic.")
			return true
		} else {
			fmt.Println("This is downstream traffic.")
			return false
		}
	}

	// 不是 IPv4 或 IPv6 数据包
	fmt.Println("Not an IPv4 or IPv6 packet.")
	//直接判断为下行
	return false
}

//记入上行部分

//记入下行部分
