package traffic

import "testing"

func TestDefaultTaskScopeFromAgentID(t *testing.T) {
	cases := map[string]int64{
		"task12":          12,
		"task12-reporter": 12,
		"task7-worker":    7,
		"worker":          0,
		"":                0,
		"task":            0,
		"taskabc":         0,
		"agent-task3":     0,
	}
	for in, want := range cases {
		if got := defaultTaskScopeFromAgentID(in); got != want {
			t.Errorf("defaultTaskScopeFromAgentID(%q) = %d, want %d", in, got, want)
		}
	}
}
