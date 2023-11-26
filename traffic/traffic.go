package traffic

import (
	"fmt"
	"sync"
	"view-net/session"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// 处理数据包流量
func HandleTraffic(packet gopacket.Packet, clientIP string, sessioninfo *session.SessionInfo, sessionMap *sync.Map) {
	//防止空指针
	if sessioninfo == nil {
		return
	}
	// 获取数据包的长度
	byteCount := sessioninfo.Bytes
	// 判断数据包是上行还是下行
	isUpTraffic := JudgeUpOrDown(packet, clientIP)
	// 更新会话流量信息
	UpdateTraffic(sessioninfo, byteCount, isUpTraffic)
}

// UpdateTraffic 方法用于更新 SessionTraffic 的信息
func UpdateTraffic(sessionInfo *session.SessionInfo, byteCount float64, isUpTraffic bool) {

	if isUpTraffic {
		sessionInfo.SessionUpTraffic += byteCount
	} else {
		sessionInfo.SessionDownTraffic += byteCount
	}
}

// JudgeUpOrDown 传入一个定义的客户端的 IPv4 或 IPv6 地址，判断数据包是上行还是下行
func JudgeUpOrDown(packet gopacket.Packet, clientIP string) bool {
	// 获取 IPv4 层
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		// IPv4 数据包
		ip, _ := ipLayer.(*layers.IPv4)
		// 判断是否是上行流量，DstIP 是目的地址，SrcIP 是源地址，因为IPv4地址是单向的，所以这里判断的是源地址
		if ip.SrcIP.String() == clientIP {
			return true
		} else {
			return false
		}
	}

	// 获取 IPv6 层
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
	// 默认判断为下行
	return false
}

// 转换流量单位
func FormatBytes(bytes float64) string {
	// 定义流量单位
	units := []string{"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"}

	// 循环判断字节数是否小于 1024
	for i := 0; i < len(units); i++ {
		if bytes < 1024 {
			return fmt.Sprintf("%.2f %s", bytes, units[i])
		}
		bytes /= 1024
	}
	// 如果循环结束还没有返回，说明字节数太大了，返回最大单位
	return fmt.Sprintf("%.2f %s", bytes, units[len(units)-1])
}
