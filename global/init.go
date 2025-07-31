package global

import (
	"sync"
)

func InitializeEngine() {
	responsesHeadersInit()
	BufferPool = newSyncPool(PduBufferSize, PduBufferSize)

	RTPRXBufferPool = newSyncPool(RTPMaxSize, RTPMaxSize)
	RTPTXBufferPool = newSyncPool(0, RTPHeaderSize+RTPPayloadSize)

	RTPBuffer = &sync.Pool{
		New: func() any {
			return make([]byte, RTPHeaderSize+RTPPayloadSize)
		},
	}
}

func newSyncPool(mysize, mycap int) *sync.Pool {
	return &sync.Pool{
		New: func() any {
			lst := make([]byte, mysize, mycap)
			return &lst
		},
	}
}
