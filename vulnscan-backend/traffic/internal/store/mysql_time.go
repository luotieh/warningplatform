package store

import "time"

// DATETIME(6) stores hits on a microsecond grid. Round both bounds of a
// [from,to) predicate upward to that grid before MySQL discards nanoseconds.
// This preserves the logical window, including a last+1ns upper bound, without
// changing an already aligned exclusive bound or admitting an earlier hit.
func mysqlHitWindowBound(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	bound := t.Truncate(time.Microsecond)
	if bound.Before(t) {
		bound = bound.Add(time.Microsecond)
	}
	return bound
}
