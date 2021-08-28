package api_test

import (
	"encoding/json"
	"fmt"

	"github.com/v2fly/v2ray-core/v4/common/api"
)

func Example() {
	result := `[
        {
            "uid": 1,
            "vmess_uid": "1727ed1f-78d0-675a-5cc8-a9a002fdf1a4",
            "speed_limit": 134217728
        },
        {
            "uid": 2,
            "vmess_uid": "d86a54d1-00a3-3677-f356-91df194adf35",
            "speed_limit": 131072
        },
        {
            "uid": 3,
            "vmess_uid": "022280d6-ccfd-8695-ee2d-3227c4cbd409",
            "speed_limit": 262144
        },
        {
            "uid": 7,
            "vmess_uid": "56e5c9ee-e725-ff60-5a2e-ff519e4adef9",
            "speed_limit": 2621440
        }
    ]`
	data := make([]*api.User, 0)
	err := json.Unmarshal([]byte(result), &data)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(data)

	//Output:
}
