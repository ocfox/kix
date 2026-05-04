package parser

import (
	"testing"
)

func TestParsePermissions(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		expect  uint32
		wantErr bool
	}{
		{"leading zero", "0700", 0o700, false},
		{"no leading zero", "700", 0o700, false},
		{"400", "400", 0o400, false},
		{"overflow", "33993", 0, true},
		{"many leading zeros", "0000111", 0o111, false},
		{"digit 8 in octal", "1000119", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePermissions(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParsePermissions(%q) expected error", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePermissions(%q): %v", tt.input, err)
			}
			if got != tt.expect {
				t.Errorf("ParsePermissions(%q) = %#o, want %#o", tt.input, got, tt.expect)
			}
		})
	}
}

func TestExtractHashes_single(t *testing.T) {
	input := "here has {{ dcd789434d890685da841b8db8a02b0173b90eac3774109ba9bca1b81440aa93 }} which should be replaced"
	got := ExtractHashes(input)
	want := []string{"dcd789434d890685da841b8db8a02b0173b90eac3774109ba9bca1b81440aa93"}
	assertHashes(t, got, want)
}

func TestExtractHashes_multi(t *testing.T) {
	input := "here {{ dcd789434d890685da841b8db8a02b0173b90eac3774109ba9bca1b81440aa93 }} {{ cd789434d890685da841b8db8a02b0173b90eac3774109ba9bca1b81440a2a93 }}"
	got := ExtractHashes(input)
	want := []string{"dcd789434d890685da841b8db8a02b0173b90eac3774109ba9bca1b81440aa93", "cd789434d890685da841b8db8a02b0173b90eac3774109ba9bca1b81440a2a93"}
	assertHashes(t, got, want)
}

func TestExtractHashes_trailingWhitespace(t *testing.T) {
	input := "{{ cd789434d890685da841b8db8a02b0173b90eac3774109ba9bca1b81440a2a93 }} "
	got := ExtractHashes(input)
	if len(got) != 1 || got[0] != "cd789434d890685da841b8db8a02b0173b90eac3774109ba9bca1b81440a2a93" {
		t.Errorf("ExtractHashes = %v", got)
	}
}

func TestExtractHashes_exact(t *testing.T) {
	input := "{{ cd789434d890685da841b8db8a02b0173b90eac3774109ba9bca1b81440a2a93 }}"
	got := ExtractHashes(input)
	if len(got) != 1 || got[0] != "cd789434d890685da841b8db8a02b0173b90eac3774109ba9bca1b81440a2a93" {
		t.Errorf("ExtractHashes = %v", got)
	}
}

func TestExtractHashes_mixedBraces(t *testing.T) {
	input := "{{ cd789434d890685da841b8db8a02b0173b90eac3774109ba9bca1b81440a2a93 }} {{ {{ c4e0ae1067d1ee736e051d7927d783bb70b032bf116f618454bf47122956d5ce }}"
	got := ExtractHashes(input)
	want := []string{"cd789434d890685da841b8db8a02b0173b90eac3774109ba9bca1b81440a2a93", "c4e0ae1067d1ee736e051d7927d783bb70b032bf116f618454bf47122956d5ce"}
	assertHashes(t, got, want)
}

func TestExtractHashes_leadingWhitespace(t *testing.T) {
	input := " {{ cd789434d890685da841b8db8a02b0173b90eac3774109ba9bca1b81440a2a93 }}"
	got := ExtractHashes(input)
	if len(got) != 1 || got[0] != "cd789434d890685da841b8db8a02b0173b90eac3774109ba9bca1b81440a2a93" {
		t.Errorf("ExtractHashes = %v", got)
	}
}

func TestExtractHashes_empty(t *testing.T) {
	if got := ExtractHashes(""); len(got) != 0 {
		t.Errorf("ExtractHashes(\"\") = %v", got)
	}
}

func TestExtractHashes_singleBrace(t *testing.T) {
	if got := ExtractHashes("{"); len(got) != 0 {
		t.Errorf("ExtractHashes(\"{\") = %v", got)
	}
}

func TestExtractHashes_multilineTruncated(t *testing.T) {
	// hash contains a newline — rejects because newline is not hex
	for _, input := range []string{
		"some {{ d9cd8155764c3543f10fad8a480d743137466f8d55213c8eaefcd12f06d43a80\n        }}",
		"some {{ d9cd8155764c3543f10fad8a480d743137466f8d55213c8eaefcd12f06d43a80 }\n        }",
	} {
		if got := ExtractHashes(input); len(got) != 0 {
			t.Errorf("ExtractHashes(%q) = %v, want nil", input, got)
		}
	}
}

func TestExtractHashes_paddedHash(t *testing.T) {
	input := "some {{ d9cd8155764c3543f10fad8a480d743137466f8d55 13c8eaefcd12f06d43a80 }}"
	if got := ExtractHashes(input); len(got) != 0 {
		t.Errorf("ExtractHashes(%q) = %v, want nil", input, got)
	}
}

func TestExtractHashes_nonHexChar(t *testing.T) {
	input := "some {{ d9cd8155764c3543f10fad8a480d743137466f8d55l13c8eaefcd12f06d43a80 }}"
	if got := ExtractHashes(input); len(got) != 0 {
		t.Errorf("ExtractHashes(%q) = %v, want nil", input, got)
	}
}

func TestExtractHashes_noHash(t *testing.T) {
	if got := ExtractHashes("some {{ }}"); len(got) != 0 {
		t.Errorf("ExtractHashes = %v", got)
	}
}

func TestExtractHashes_shortHash(t *testing.T) {
	input := "some {{ 8155764c3543f10fad8a480d743137466f8d55213c8eaefcd12f06d43a80 }}"
	if got := ExtractHashes(input); len(got) != 0 {
		t.Errorf("ExtractHashes(%q) = %v, want nil", input, got)
	}
}

func TestExtractHashes_unclosed(t *testing.T) {
	input := "some {{ 8155764c3543f10fad8a480d743137466f8d55213c8eaefcd12f06d43a80"
	if got := ExtractHashes(input); len(got) != 0 {
		t.Errorf("ExtractHashes(%q) = %v, want nil", input, got)
	}
}

func TestExtractHashes_malformed(t *testing.T) {
	input := "some {{ 8155{{764c3543f10fad8a480d743137466f8d55213c8eaefcd12f06d43a\\8}}0"
	if got := ExtractHashes(input); len(got) != 0 {
		t.Errorf("ExtractHashes(%q) = %v, want nil", input, got)
	}
}

func TestExtractHashes_fuzzCrash(t *testing.T) {
	// Regression: must not panic on this input.
	input := "{{ EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE9EEEEEEEEEEEEEEEEEE1A }}{"
	_ = ExtractHashes(input)
}

func assertHashes(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("got len=%d, want len=%d: %v", len(got), len(want), got)
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("hash[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}
