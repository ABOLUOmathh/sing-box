package onesocks

import "testing"

func TestParsePaddingLen(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"", 0},
		{"0-0", 0},
		{"8-8", 0},
		{"64-8", 0},
		{"8-9", 8},
	}

	for _, tt := range tests {
		got, err := ParsePaddingLen(tt.input)
		if err != nil {
			t.Fatalf(
				"ParsePaddingLen(%q): %v",
				tt.input,
				err,
			)
		}

		if got != tt.want {
			t.Fatalf(
				"ParsePaddingLen(%q) = %d, want %d",
				tt.input,
				got,
				tt.want,
			)
		}
	}
}

func TestPaddingRange(t *testing.T) {
	for i := 0; i < 1000; i++ {
		got, err := ParsePaddingLen("8-64")
		if err != nil {
			t.Fatal(err)
		}

		if got < 8 || got >= 64 {
			t.Fatalf(
				"padding = %d, want [8,64)",
				got,
			)
		}
	}
}

func TestRejectBadPaddingSpec(t *testing.T) {
	bad := []string{
		"8",
		"a-b",
		"1-2-3",
		"300-301",
	}

	for _, value := range bad {
		if _, err := ParsePaddingLen(value); err == nil {
			t.Fatalf(
				"expected error for %q",
				value,
			)
		}
	}
}
