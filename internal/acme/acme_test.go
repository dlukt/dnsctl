package acme

import (
	"testing"
)

// TestContainsPrefix tests the case-insensitive prefix checking
func TestContainsPrefix(t *testing.T) {
	tests := []struct {
		name   string
		s      string
		prefix string
		want   bool
	}{
		{
			name:   "exact match",
			s:      "_acme-challenge.",
			prefix: "_acme-challenge.",
			want:   true,
		},
		{
			name:   "prefix match",
			s:      "_acme-challenge.www.example.com.",
			prefix: "_acme-challenge.",
			want:   true,
		},
		{
			name:   "case insensitive - uppercase prefix",
			s:      "_acme-challenge.example.com.",
			prefix: "_ACME-CHALLENGE.",
			want:   true,
		},
		{
			name:   "case insensitive - uppercase string",
			s:      "_ACME-CHALLENGE.example.com.",
			prefix: "_acme-challenge.",
			want:   true,
		},
		{
			name:   "case insensitive - mixed case",
			s:      "_AcMe-ChAlLeNgE.example.com.",
			prefix: "_acme-challenge.",
			want:   true,
		},
		{
			name:   "no match - different prefix",
			s:      "www.example.com.",
			prefix: "_acme-challenge.",
			want:   false,
		},
		{
			name:   "no match - shorter string",
			s:      "_acme",
			prefix: "_acme-challenge.",
			want:   false,
		},
		{
			name:   "empty string",
			s:      "",
			prefix: "_acme-challenge.",
			want:   false,
		},
		{
			name:   "empty prefix",
			s:      "anything",
			prefix: "",
			want:   true,
		},
		{
			name:   "both empty",
			s:      "",
			prefix: "",
			want:   true,
		},
		{
			name:   "partial prefix match - not at start",
			s:      "www._acme-challenge.example.com.",
			prefix: "_acme-challenge.",
			want:   false,
		},
		{
			name:   "numbers in string",
			s:      "_acme-challenge123.example.com.",
			prefix: "_acme-challenge",
			want:   true,
		},
		{
			name:   "special characters",
			s:      "_dmarc.example.com.",
			prefix: "_dmarc.",
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsPrefix(tt.s, tt.prefix)
			if got != tt.want {
				t.Errorf("containsPrefix(%q, %q) = %v, want %v",
					tt.s, tt.prefix, got, tt.want)
			}
		})
	}
}

// TestContainsPrefixCaseConversion tests the case conversion logic
func TestContainsPrefixCaseConversion(t *testing.T) {
	// Test that uppercase letters A-Z are correctly converted to lowercase
	uppercase := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowercase := "abcdefghijklmnopqrstuvwxyz"

	for i := 0; i < 26; i++ {
		s := string(uppercase[i]) + "test"
		prefix := string(lowercase[i]) + "test"

		if !containsPrefix(s, prefix) {
			t.Errorf("containsPrefix(%q, %q) should be true", s, prefix)
		}
	}
}

// TestContainsPrefixNonAlpha tests that non-alpha characters are handled correctly
func TestContainsPrefixNonAlpha(t *testing.T) {
	// Non-alpha characters should match exactly, but alpha chars are case-insensitive
	tests := []struct {
		s      string
		prefix string
		want   bool
	}{
		{"123abc", "123", true},
		{"123abc", "123ABC", true}, // alpha chars are case-insensitive
		{"_test", "_test", true},
		{"-test", "-test", true},
		{"1234567890", "1234567890", true},
	}

	for _, tt := range tests {
		got := containsPrefix(tt.s, tt.prefix)
		if got != tt.want {
			t.Errorf("containsPrefix(%q, %q) = %v, want %v", tt.s, tt.prefix, got, tt.want)
		}
	}
}
