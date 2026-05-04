package parser

import (
	"fmt"
	"strconv"
	"strings"
)

func ParsePermissions(s string) (uint32, error) {
	s = strings.TrimPrefix(s, "0")
	mode, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("parse permissions %q: %w", s, err)
	}
	return uint32(mode), nil
}

func ExtractHashes(input string) []string {
	const minLen = len("{{ ") + 64 + len(" }}")

	if len(input) < minLen {
		return nil
	}

	for i := 0; i <= len(input)-minLen; i++ {
		if !strings.HasPrefix(input[i:], "{{ ") {
			continue
		}

		hashStart := i + len("{{ ")
		hashEnd := hashStart + 64

		if hashEnd+len(" }}") > len(input) {
			continue
		}

		if input[hashEnd:hashEnd+len(" }}")] != " }}" {
			continue
		}

		hashStr := input[hashStart:hashEnd]
		if !isHex(hashStr) {
			continue
		}

		rest := input[hashEnd+len(" }}"):]
		return append([]string{hashStr}, ExtractHashes(rest)...)
	}

	return nil
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
