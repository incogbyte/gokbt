package util

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseKdcDelays parses "host:port=100,other:88=200" into map[string]time.Duration (ms)
func ParseKdcDelays(raw string) (map[string]time.Duration, error) {
	res := map[string]time.Duration{}
	if strings.TrimSpace(raw) == "" {
		return res, nil
	}
	entries := strings.Split(raw, ",")
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid entry %q", e)
		}
		host := strings.TrimSpace(parts[0])
		if host == "" {
			return nil, fmt.Errorf("empty host in %q", e)
		}
		ms, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return nil, fmt.Errorf("invalid delay in %q: %w", e, err)
		}
		res[host] = time.Duration(ms) * time.Millisecond
	}
	return res, nil
}

