package main

import (
	"testing"
	"time"
)

func TestDisplayMoscowTime(t *testing.T) {
	utc := time.Date(2026, time.July, 27, 12, 36, 0, 0, time.UTC)
	if got := displayMoscowTime(utc); got != "15:36" {
		t.Fatalf("displayMoscowTime() = %q, want 15:36", got)
	}
}
