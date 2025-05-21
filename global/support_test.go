package global

import (
	"reflect"
	"testing"
)

func TestStr2IntDefaultMinMax(t *testing.T) {
	t.Parallel()
	deflt := 0
	mini := 0
	maxi := 500
	tests := []struct {
		input    string
		defaultV int
		min      int
		max      int
		expected int
		valid    bool
	}{
		{"123", deflt, mini, maxi, 123, true},
		{"-", deflt, mini, maxi, 0, false},
		{"-0", deflt, mini, maxi, 0, true},
		{"+50", deflt, mini, maxi, 50, true},
		{"-123", deflt, mini, maxi, 0, false},
		{"abc", deflt, mini, maxi, 0, false},
		{"", deflt, mini, maxi, 0, false},
		{"99", deflt, mini, maxi, 99, true},
		{"-300", deflt, mini, maxi, 0, false},
		{"0", deflt, mini, maxi, 0, true},
		{"499", deflt, mini, maxi, 499, true},
		{"500", deflt, mini, maxi, 500, true},
		{"501", deflt, mini, maxi, 0, false},
	}

	for _, test := range tests {
		result, valid := Str2IntDefaultMinMax(test.input, test.defaultV, test.min, test.max)
		if result != test.expected || valid != test.valid {
			t.Errorf("Str2IntDefaultMinimum(%q, %d, %d) = (%d, %v); want (%d, %v)",
				test.input, test.defaultV, test.min, result, valid, test.expected, test.valid)
		}
	}
}

func TestCleanAndSplitHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		dropDQ   bool
		expected map[string]string
	}{
		{
			input:  `multipart/mixed;boundary=unique-boundary-1`,
			dropDQ: false,
			expected: map[string]string{
				"!headerValue": "multipart/mixed",
				"boundary":     "unique-boundary-1",
			},
		},
		{
			input:  `application/sdp`,
			dropDQ: false,
			expected: map[string]string{
				"!headerValue": "application/sdp",
			},
		},
	}

	for _, test := range tests {
		result := CleanAndSplitHeader(test.input, test.dropDQ)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("CleanAndSplitHeader(%q, %v) = %v; want %v", test.input, test.dropDQ, result, test.expected)
		}
	}

	for _, test := range tests {
		result := ExtractParameters(test.input, true)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("ExtractParameters(%q, %v) = %v; want %v", test.input, true, result, test.expected)
		}
	}

}
