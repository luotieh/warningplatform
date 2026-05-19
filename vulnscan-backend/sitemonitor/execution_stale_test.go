package sitemonitor

import (
	"testing"
	"time"
)

func TestStaleTimeoutForDimension(t *testing.T) {
	if StaleTimeoutForDimension("tamper") < StaleTimeoutForDimension("availability") {
		t.Fatal("tamper timeout should be >= availability")
	}
	if StaleTimeoutForDimension("tamper") < 5*time.Minute {
		t.Fatal("tamper timeout too short")
	}
}
