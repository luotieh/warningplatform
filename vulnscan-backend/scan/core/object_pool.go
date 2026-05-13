package core

import (
	"bytes"
	"sync"
)

var (
	bufferPool  sync.Pool
	findingPool sync.Pool
)

func init() {
	bufferPool = sync.Pool{
		New: func() interface{} {
			return &bytes.Buffer{}
		},
	}

	findingPool = sync.Pool{
		New: func() interface{} {
			return &Finding{}
		},
	}
}

func AcquireBuffer() *bytes.Buffer {
	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	return buf
}

func ReleaseBuffer(buf *bytes.Buffer) {
	buf.Reset()
	bufferPool.Put(buf)
}

func AcquireFinding() *Finding {
	f := findingPool.Get().(*Finding)
	*f = Finding{}
	return f
}

func ReleaseFinding(f *Finding) {
	f.Target = nil
	f.CVEIDs = nil
	f.CWEIDs = nil
	f.Data = nil
	findingPool.Put(f)
}
