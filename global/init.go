package global

import (
	"sync"
)

func InitializeEngine() {
	responsesHeadersInit()
	BufferPool = newSyncPool(PduBufferSize, PduBufferSize)

	rtpsz := RTPHeaderSize + RTPPayloadSize
	RTPRXBufferPool = newSyncPool(rtpsz, rtpsz)
	RTPTXBufferPool = newSyncPool(0, rtpsz)
}

func newSyncPool(sz, cap int) *sync.Pool {
	return &sync.Pool{
		New: func() any {
			lst := make([]byte, sz, cap)
			return &lst
		},
	}
}
