package subtocheck

import (
	"testing"
)

func TestPtrToStr(t *testing.T) {
	result := PtrToStr("test string")
	if *result != "test string" {
		t.Error("PtrToStr Failed")
	}
}
