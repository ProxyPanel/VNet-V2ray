package buf

import (
	"context"

	"golang.org/x/time/rate"
)

type LimitReader struct {
	context.Context
	*rate.Limiter
	Reader
}

func (l *LimitReader) SetLimiter(limiter *rate.Limiter) {
	l.Limiter = limiter
}

func (l *LimitReader) ReadMultiBuffer() (MultiBuffer, error) {
	if l.Limiter == nil {
		return l.Reader.ReadMultiBuffer()
	}

	mb, err := l.Reader.ReadMultiBuffer()
	if err != nil {
		return mb, err
	}

	mbLen := int(mb.Len())
	//fmt.Println(fmt.Sprintf("读取: %d", mbLen))
	if mbLen > l.Limiter.Burst() {
		for {
			err = l.Limiter.WaitN(l.Context, l.Burst())
			if err != nil {
				return nil, err
			}
			mbLen -= l.Burst()
			if mbLen <= l.Burst() {
				break
			}
		}
	}

	err = l.Limiter.WaitN(l.Context, mbLen)
	if err != nil {
		return nil, err
	}
	return mb, err
}

type LimitWriter struct {
	context.Context
	*rate.Limiter
	Writer
}

func (l *LimitWriter) SetLimiter(limiter *rate.Limiter) {
	l.Limiter = limiter
}

func (l *LimitWriter) WriteMultiBuffer(mb MultiBuffer) error {
	if l.Limiter == nil {
		return l.Writer.WriteMultiBuffer(mb)
	}

	mbLen := int(mb.Len())
	//fmt.Println(fmt.Sprintf("写入: %d", mbLen))
	err := l.Writer.WriteMultiBuffer(mb)
	if err != nil {
		return err
	}

	if mbLen > l.Burst() {
		for {
			err = l.Limiter.WaitN(l.Context, l.Burst())
			if err != nil {
				return err
			}
			mbLen -= l.Burst()
			if mbLen <= l.Burst() {
				break
			}
		}
	}
	return l.Limiter.WaitN(l.Context, mbLen)
}

type PipeLimiter struct {
	Limit      uint64
	UpLimiter  *rate.Limiter
	DownLimter *rate.Limiter
}

func NewPipeLimiter(limit uint64) *PipeLimiter {
	p := new(PipeLimiter)
	p.Limit = limit
	p.UpLimiter = rate.NewLimiter(rate.Limit(limit), int(limit))
	p.DownLimter = rate.NewLimiter(rate.Limit(limit), int(limit))
	return p
}

type ProxyLimiter struct {
	Limit  uint64
	Source *PipeLimiter
	Dest   *PipeLimiter
}

func NewProxyLimiter(limit uint64) *ProxyLimiter {
	p := new(ProxyLimiter)
	p.Limit = limit
	p.Source = NewPipeLimiter(limit)
	p.Dest = NewPipeLimiter(limit)
	return p
}
