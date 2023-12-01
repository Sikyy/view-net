package test

import (
	"testing"
	"view-net/junge"
)

func TestParseHTTPRequest(t *testing.T) {

	httpRequestStr := `GET /ME8wTTBLMEkwRzAHBgUrDgMCGgQU36oS4yixCUGT4p9Cgs5HQEKVWKMEFLE%2Bw2kD%2BL9HAdSYJhoIAu9jZCvDAhAHF3kRAF0iZ%2FaIkvaPi1BY HTTP/1.1
Host: ocsp.digicert.com
X-Apple-Request-UUID: 36F408BF-1EE2-4523-907B-19A390F2A4C1
Accept: */*
User-Agent: com.apple.trustd/3.0
Accept-Language: zh-CN,zh-Hans;q=0.9
Accept-Encoding: gzip, deflate
Connection: keep-alive`

	// 使用正则表达式提取主机名和路径
	method, host, path := junge.ExtractHTTPMethodHostPathFromRequest(httpRequestStr)
	t.Logf("Method: %s, Host: %s, Path: %s", method, host, path)
}
