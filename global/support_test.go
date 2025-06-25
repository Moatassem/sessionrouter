package global_test

import (
	"SRGo/global"
	"fmt"
	"reflect"
	"sync"
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
		minlmt   int
		maxlmt   int
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
		result, valid := global.Str2IntDefaultMinMax(test.input, test.defaultV, test.minlmt, test.maxlmt)
		if result != test.expected || valid != test.valid {
			t.Errorf("Str2IntDefaultMinimum(%q, %d, %d) = (%d, %v); want (%d, %v)",
				test.input, test.defaultV, test.minlmt, result, valid, test.expected, test.valid)
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
		result := global.CleanAndSplitHeader(test.input, test.dropDQ)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("CleanAndSplitHeader(%q, %v) = %v; want %v", test.input, test.dropDQ, result, test.expected)
		}
	}

	for _, test := range tests {
		result := global.ExtractParameters(test.input, true)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("ExtractParameters(%q, %v) = %v; want %v", test.input, true, result, test.expected)
		}
	}
}

func TestBuildUdpAddr2(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		valid    bool
		expected string
	}{
		{
			input:    "somewhere:5070",
			valid:    true,
			expected: "somewhere:5070",
		},
		{
			input:    "somewhere:0",
			valid:    false,
			expected: "",
		},
		{
			input:    "somewhere",
			valid:    true,
			expected: "somewhere",
		},
		{
			input:    "192.168.1.2:5070",
			valid:    false,
			expected: "192.168.1.2:5070",
		},
		{
			input:    "192.168.1.2:0",
			valid:    false,
			expected: "",
		},
		{
			input:    "192.168.1.2",
			valid:    false,
			expected: "192.168.1.2",
		},
	}

	for _, test := range tests {
		result, err := global.BuildUdpSocket(test.input, 5060)
		if err != nil && test.valid {
			t.Errorf("BuildUdpSocket(%q, 5060) returned %v but expected %v", test.input, result, test.expected)
		}
		if result != nil && result.String() != test.expected {
			t.Errorf("BuildUdpSocket(%q, 5060) = %v; want %v", test.input, result.String(), test.expected)
		}
	}
}

// func BenchmarkSyncPool(b *testing.B) {

// 	b.ReportAllocs()

// 	b.Run("With Pointers", func(b *testing.B) {
// 		pool := &sync.Pool{
// 			New: func() any {
// 				lst := make([]byte, 512)
// 				return &lst
// 			},
// 		}
// 		for b.Loop() {
// 			buf := pool.Get().(*[]byte)
// 			// Simulate some work with the buffer
// 			for i := range *buf {
// 				(*buf)[i] = byte(i % 256)
// 			}
// 			pool.Put(buf)
// 		}
// 	})

// 	b.Run("Without Pointers", func(b *testing.B) {
// 		pool := &sync.Pool{
// 			New: func() any {
// 				return make([]byte, 512)
// 			},
// 		}
// 		for b.Loop() {
// 			buf := pool.Get().([]byte)
// 			// Simulate some work with the buffer
// 			for i := range buf {
// 				buf[i] = byte(i % 256)
// 			}
// 			pool.Put(buf)
// 		}
// 	})
// }

func BenchmarkSyncPool(b *testing.B) {
	// b.ReportAllocs()

	fmt.Println(global.GetNTPTimestamp())

	// Pointer version (efficient, no allocations)
	b.Run("With Pointers", func(b *testing.B) {
		// var count atomic.Int64
		// var goroutines atomic.Int64
		pool := &sync.Pool{
			New: func() any {
				// count.Add(1)
				lst := make([]byte, 512)
				return &lst
			},
		}
		for b.Loop() {
			go func() {
				buf := pool.Get().(*[]byte)
				for i := range *buf {
					(*buf)[i] = byte(i % 256)
				}
				pool.Put(buf)
				// goroutines.Add(1)
			}()
		}

		// fmt.Printf("With Pointers\nTotal buffers created: %d, Total goroutines: %d\n", count.Load(), goroutines.Load())
	})

	// Optimized non-pointer version (zero allocations)
	b.Run("Without Pointers", func(b *testing.B) {
		// var count atomic.Int64
		// var goroutines atomic.Int64
		pool := &sync.Pool{
			New: func() any {
				// count.Add(1)
				return make([]byte, 512)
			},
		}
		for b.Loop() {
			go func() {
				// goroutines.Add(1)
				buf := pool.Get().([]byte)
				// Re-slice to full capacity to ensure proper length
				// buf = buf[:512]
				for i := range buf {
					buf[i] = byte(i % 256)
				}
				// Reset slice length to 0 before returning to pool
				pool.Put(buf)
			}()
		}
		// fmt.Printf("Without Pointers\nTotal buffers created: %d, Total goroutines: %d\n", count.Load(), goroutines.Load())
	})

	b.Run("Array Pointer", func(b *testing.B) {
		// var count atomic.Int64
		// var goroutines atomic.Int64
		pool := &sync.Pool{
			New: func() any {
				// count.Add(1)
				return new([512]byte)
			},
		}
		for b.Loop() {
			go func() {
				// goroutines.Add(1)
				arr := pool.Get().(*[512]byte)
				// Direct array access - most efficient
				for i := range len(arr) {
					arr[i] = byte(i % 256)
				}
				pool.Put(arr)
			}()
		}
		// fmt.Printf("Array Pointer\nTotal buffers created: %d, Total goroutines: %d\n", count.Load(), goroutines.Load())
	})
}
