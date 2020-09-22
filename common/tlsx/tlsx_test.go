package tlsx_test

import (
	"fmt"
	"v2ray.com/core/common/tlsx"
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
