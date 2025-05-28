package global

import (
	"sync"
)

func InitializeEngine() {
	responsesHeadersInit()
	BufferPool = newSyncPool()
}

func newSyncPool() *sync.Pool {
	return &sync.Pool{
		New: func() any {
			lst := make([]byte, PduBufferSize)
			return &lst
		},
	}
}
