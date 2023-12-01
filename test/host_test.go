package test

import (
	"fmt"
	"log"
	"sync"
	"testing"
	"view-net/host"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var wg sync.WaitGroup

// sudo 启动  已测试成功
func TestHandleHTTPPacket(t *testing.T) {
	// 对网卡流量进行实时捕获
	// 获取本机所有网络接口的信息
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	// 遍历所有网络接口
	for _, iface := range interfaces {
		fmt.Printf("Capturing traffic on interface %s...\n", iface.Name)
		wg.Add(1)
		// 在新的协程中捕获数据包
		go GetPack(iface.Name)
	}
	wg.Wait()

}
func GetPack(ifaceName string) {
	defer wg.Done()

	handler, err := pcap.OpenLive(ifaceName, 65535, false, pcap.BlockForever)
	if err != nil {
		log.Fatalln(err)
	}
	defer handler.Close()
	// 获取包源
	source := gopacket.NewPacketSource(handler, handler.LinkType())
	for packet := range source.Packets() {
		host.HandleHTTPPorHTTPSPacket(packet)
	}
}
