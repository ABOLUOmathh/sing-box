package onesocks

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
)

// ParsePaddingLen mirrors the recovered native OneSocks parser:
//
// empty  -> "0-0"
// "a-b"  -> rand.Intn(b-a)+a when b-a > 0
// b-a<=0 -> 0
//
// The native implementation stores the selected length in one byte.
// Values above 255 are rejected here instead of allowing protocol
// desynchronization.
func ParsePaddingLen(value string) (int, error) {
	if value == "" {
		value = "0-0"
	}

	parts := strings.Split(value, "-")
	if len(parts) != 2 {
		return 0, fmt.Errorf(
			"onesocks: padding-len must be like xx-xx",
		)
	}

	minValue, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, fmt.Errorf(
			"onesocks: parse padding minimum: %w",
			err,
		)
	}

	maxValue, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, fmt.Errorf(
			"onesocks: parse padding maximum: %w",
			err,
		)
	}

	delta := maxValue - minValue
	if delta <= 0 {
		return 0, nil
	}

	// #nosec G404 -- math/rand is required to mirror native protocol
	// padding-length selection; this is not cryptographic randomness.
	paddingLen := rand.Intn(delta) + minValue

	if paddingLen < 0 || paddingLen > 255 {
		return 0, fmt.Errorf(
			"onesocks: padding length %d is outside byte range",
			paddingLen,
		)
	}

	return paddingLen, nil
}
