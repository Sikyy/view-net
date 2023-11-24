package session

import (
	"sync"
)

// 在 help 包中定义一个全局的 sync.Map
var SessionMap sync.Map

// SessionInfo 会话信息
type SessionInfo struct {
	ID             int64              // 会话ID
	Name           string             // 会话名称
	SrcMAC         string             // 源MAC地址
	SrcIP          string             // 源IP地址
	SrcPort        int                // 源端口号
	DstMAC         string             // 目的MAC地址
	DstIP          string             // 目的IP地址
	DstPort        int                // 目的端口号
	Protocol       string             // 协议号
	TCPStatus      string             // TCP状态
	udpStatus      string             // UDP状态
	SessionTraffic SessionTrafficInfo // 会话流量信息
}

// 数据包流量信息
type AutoDataTrafficInfo struct {
	DataUpTraffic   float64 //上行流量
	DataDownTraffic float64 //下行流量
}

// SessionTrafficInfo 会话流量信息
type SessionTrafficInfo struct {
	UpTraffic   float64 // 上行流量
	DownTraffic float64 // 下行流量
}
