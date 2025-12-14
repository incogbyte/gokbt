package util

import (
	"math/rand"
	"time"
)

func JitterDelay(baseMs int, jitterMs int) time.Duration {
	if jitterMs <= 0 {
		return time.Duration(baseMs) * time.Millisecond
	}
	
	minDelay := baseMs - jitterMs
	if minDelay < 0 {
		minDelay = 0
	}
	maxDelay := baseMs + jitterMs
	
	actualDelay := minDelay + rand.Intn(maxDelay-minDelay+1)
	return time.Duration(actualDelay) * time.Millisecond
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

