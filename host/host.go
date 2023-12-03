package host

import (
	"fmt"
	"regexp"
	"strings"
	"view-net/session"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func HandleHTTPPorHTTPSPacket(packet gopacket.Packet, sessionInfo *session.SessionInfo) (string, string) {

	ethernetPacket, _ := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	ip, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	applicationLayer := packet.ApplicationLayer()

	if ethernetPacket == nil || ip == nil || tcp == nil || applicationLayer == nil {
		return "", ""
	}

	payload := string(applicationLayer.Payload())

	if isHTTP(packet, payload) {
		if strings.HasPrefix(payload, "GET") || strings.HasPrefix(payload, "POST") || strings.HasPrefix(payload, "PUT") || strings.HasPrefix(payload, "DELETE") || strings.HasPrefix(payload, "HEAD") || strings.HasPrefix(payload, "TRACE") || strings.HasPrefix(payload, "OPTIONS") {
			reg := regexp.MustCompile(`(?s)(GET|POST|PUT|DELETE|HEAD|TRACE|OPTIONS) (.*?) HTTP.*Host: (.*?)\n`)
			if reg == nil {
				fmt.Println("MustCompile err")
				return "", ""
			}
			//result【0】是全部
			//result【1】是GET/POST/PUT/DELETE/HEAD/TRACE/OPTIONS
			//result【2】是url
			//result【3】是host

			result := reg.FindStringSubmatch(payload)
			if len(result) == 4 {
				result[2] = strings.TrimSpace(result[2])
				result[3] = strings.TrimSpace(result[3])
				url := "http://" + result[3] + result[2]
				fmt.Println("--------------------------------------------------------------------")
				fmt.Println("请求头:", result[0])
				fmt.Println("请求方法: ", result[1])
				fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
				fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
				fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
				fmt.Println("Protocol: ", ip.Protocol)
				fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
				fmt.Println("Sequence number: ", tcp.Seq)
				fmt.Println("url:", url)
				fmt.Println("host:", result[3])
				host := result[3]
				method := result[1]
				return host, method
			}
		}
	} else if isHTTPS(packet) {
		fmt.Println("--------------------------------------------------------------------")
		fmt.Println("方法为:HTTPS")
		fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
		fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
		fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		fmt.Println("Protocol: ", ip.Protocol)
		fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
		fmt.Println("Sequence number: ", tcp.Seq)
		host := "HTTPS:443"
		method := "HTTPS"
		return host, method

	} else {
		fmt.Println("--------------------------------------------------------------------")
		fmt.Println("方法为:TCP")
		host := "???"
		method := "TCP"
		return host, method
	}
	return "Unknow", "Unknow"
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
func isHTTP(packet gopacket.Packet, payload string) bool {
	transportLayer := packet.TransportLayer()
	// 检查是否为TCP流量
	if transportLayer != nil && transportLayer.LayerType() == layers.LayerTypeTCP {
		tcp := transportLayer.(*layers.TCP)
		// 检查是否为HTTP端口
		if tcp.DstPort == 80 {
			applicationLayer := packet.ApplicationLayer()
			// 检查是否包含HTTP请求方法
			if applicationLayer != nil && (strings.HasPrefix(payload, "GET") || strings.HasPrefix(payload, "POST") || strings.HasPrefix(payload, "PUT") || strings.HasPrefix(payload, "DELETE") || strings.HasPrefix(payload, "HEAD") || strings.HasPrefix(payload, "TRACE") || strings.HasPrefix(payload, "OPTIONS")) {
				return true
			}
		}
	}
	return false
}
