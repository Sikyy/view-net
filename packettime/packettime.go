package packttime

import (
	"sync"
	"time"
	"view-net/session"

	"github.com/google/gopacket"
)

func HandleTime(packet gopacket.Packet, sessioninfo *session.SessionInfo, sessionMap *sync.Map) {
	//防止空指针
	if sessioninfo == nil {
		return
	}

	// 获取数据包的时间戳
	packetTime := packet.Metadata().Timestamp
	// 更新时间信息
	UpdateTime(packetTime, sessioninfo)
}

// UpdateTime 方法用于更新 SessionTime 的信息
func UpdateTime(packetTime time.Time, sessionInfo *session.SessionInfo) {
	// 如果是第一次捕获到数据包，将当前时间赋值给 SessionTime.StartTime
	if sessionInfo.StartTime.IsZero() {
		sessionInfo.StartTime = packetTime
	} else {
		// 如果是第二次捕获到数据包，将当前时间赋值给 SessionTime.EndTime
		sessionInfo.EndTime = packetTime
	}
}
