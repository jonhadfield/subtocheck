package subtocheck

import (
	"os"
	"strings"

	"golang.org/x/term"
)

// terminalWidth returns the width of the terminal on stdout, or 80 if there is none.
func terminalWidth() int {
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || width <= 0 {
		return 80
	}
	return width
}

func contains(s []int, e int) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func getStringInBetween(str string, start string, end string) (result string) {
	s := strings.Index(str, start)
	if s == -1 {
		return
	}
	s += len(start)
	e := strings.Index(str, end)
	return str[s:e]
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

// PtrToStr returns a pointer to an existing string
func PtrToStr(s string) *string {
	return &s
}
