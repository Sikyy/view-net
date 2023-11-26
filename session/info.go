package session

import (
	"sync"
	"time"
)

// 在 help 包中定义一个全局的 sync.Map
var SessionMap sync.Map

// SessionInfo 会话信息
type SessionInfo struct {
	ID                 int64     // 会话ID
	Name               string    // 会话名称
	Bytes              float64   // 数据包的长度
	Time               time.Time // 数据包的时间
	SrcMAC             string    // 源MAC地址
	SrcIP              string    // 源IP地址
	SrcPort            int       // 源端口号
	DstMAC             string    // 目的MAC地址
	DstIP              string    // 目的IP地址
	DstPort            int       // 目的端口号
	Protocol           string    // 协议号
	TCPStatus          string    // TCP状态
	udpStatus          string    // UDP状态
	SessionUpTraffic   float64   // 会话上行流量信息
	SessionDownTraffic float64   // 会话下行
	StartTime          time.Time //会话开始时间
	EndTime            time.Time //会话结束时间
}
