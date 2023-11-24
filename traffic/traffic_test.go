package traffic

import (
	"fmt"
	"testing"
)

func TestFormatBytes(t *testing.T) {
	str := FormatBytes(10000857.0)
	fmt.Println(str)
}
