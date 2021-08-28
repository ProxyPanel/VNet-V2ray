package tlsx_test

import (
	"fmt"

	"github.com/v2fly/v2ray-core/v4/common/tlsx"
)

func ExampleGenerateCAWithECC() {
	key, cert, err := tlsx.GenerateCAWithECC()
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println(string(cert))
	fmt.Println()
	fmt.Println(string(key))

	//Output:
}
