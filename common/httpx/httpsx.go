package httpx

import (
	"fmt"
	"net/http"
	"time"
)

func Http302(redirectUrl string) string {
	template := "HTTP/1.1 302 Moved Temporarily\r\n"
	template += "Server: nginx\r\n"
	template += fmt.Sprintf("Location: %s\r\n\r\n", redirectUrl)
	return template
}

// Http403 return 403 Forbidden
func Http403(content string) string {
	template := "HTTP/1.1 403 Forbidden\r\n"
	template += fmt.Sprintf("Date: %s\r\n", time.Now().Format(http.TimeFormat))
	template += "Content-Type: text/html; charset=utf-8\r\n"
	template += fmt.Sprintf("Content-Length: %d\r\n", len(content))
	template += "\r\n"
	template += content
	return template
}
