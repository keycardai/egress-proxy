package exchange

import "time"

// SetClock replaces the clock the cache reads, so a test can move time
// without waiting.
func SetClock(s *AssertionSource, now func() time.Time) {
	s.now = now
}
